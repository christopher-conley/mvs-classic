//! The relay's link to a registry (`server::Options::registry`): it dials the registry, starts the link as
//! `mvs_protocol::registry_wire` has it, checks in with its public address and its load, beats, and keeps the relays
//! the registry tells it of. A link that ends is dialed again after a wait that grows; the relay serves its players
//! all along.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvs_protocol::registry_wire::{
    Counts, FromRegistry, REGISTRY_WIRE_VERSION, RelayEntry, ToRegistry, registry_handshake_bytes,
};
use mvs_protocol::relay_seal::{KX_BYTES, KxSecret, SealedReader, TxSeal, derive, shared, split};
use mvs_protocol::relay_wire::{
    FT_JSON, Frame, FrameReader, NONCE_BYTES, RELAY_WIRE_VERSION, Side, Transcript, bad_public_key, json_frame, key_id,
    parse_address, read_json,
};
use mvs_protocol::version::PROTOCOL;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{Instant, timeout_at};

use crate::core::Core;
use crate::server::{Log, RegistryOptions};

/// Why a link ended, as its log line has it: the relay's own texts, or a registry's refusal.
const NO_ADDRESS: &str = "the registry's address is not one";
const NO_CONNECTION: &str = "could not connect";
const SLOW_START: &str = "the start took too long";
const OTHER_KEY: &str = "the registry at that address proved another key";
const BAD_SIGNATURE: &str = "bad signature";
const BAD_CHALLENGE: &str = "bad challenge";
const OTHER_VERSION: &str = "the registry speaks another link version";
const BAD_FRAME: &str = "bad frame";
const BAD_MESSAGE: &str = "bad message";
const CLOSED: &str = "the registry closed the link";
const BROKEN: &str = "the link broke";
const QUIET: &str = "the registry went quiet";
/// A refusal whose reason is not one to log (too long, or not plain printable text).
const REFUSED: &str = "refused";

/// What the link last heard, read by `Relay::registry_relays` and `Relay::registry_up`.
#[derive(Default)]
pub(crate) struct Kept {
    pub(crate) up: Cell<bool>,
    pub(crate) relays: RefCell<BTreeMap<String, RelayEntry>>,
}

/// What the link runs with.
pub(crate) struct Link {
    pub(crate) o: RegistryOptions,
    pub(crate) key: SigningKey,
    pub(crate) log: Log,
    /// The relay's load now, read in one borrow of the core.
    pub(crate) counts: Box<dyn Fn() -> Counts>,
    pub(crate) kept: Rc<Kept>,
}

/// A limit or a count as the wire has it: floored, at most `u32::MAX`, 0 for none or NaN.
fn count(v: f64) -> u32 {
    // (`as` saturates, and makes NaN 0)
    v.floor() as u32
}

/// The core's load as the wire has it.
pub(crate) fn counts_of(core: &Core) -> Counts {
    let limits = core.limits();
    Counts {
        players: u32::try_from(core.players()).unwrap_or(u32::MAX),
        max_players: count(limits.players),
        matches: u32::try_from(core.matches()).unwrap_or(u32::MAX),
        max_matches: count(limits.matches),
    }
}

/// `v` ms as a Duration: 0 for a negative or NaN one, a long time for one past range.
fn duration(v: f64) -> Duration {
    Duration::from_secs_f64(if v > 0.0 { v.min(1e12) / 1000.0 } else { 0.0 })
}

/// Standard base64 of exactly `N` bytes, else None.
fn unb64<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() > 4 * N.div_ceil(3) {
        return None;
    }
    STANDARD.decode(s).ok()?.try_into().ok()
}

/// A registry's refusal as a log line may have it: its reason when that is short plain text, else REFUSED.
fn refusal(why: &str) -> String {
    if !why.is_empty() && why.len() <= 120 && why.bytes().all(|b| (b' '..=b'~').contains(&b)) {
        why.to_owned()
    } else {
        REFUSED.to_owned()
    }
}

fn say(l: &Link, line: &str) {
    (l.log.borrow_mut())(line);
}

/// The link's whole life: a try, and after its end a wait (growing from `retry_ms.0` to `retry_ms.1`, the first again
/// after a welcome) and the next. The log has one line when the link is lost and one when it is checked in, not one
/// for each try.
pub(crate) async fn run(l: Link) {
    let (first, longest) = l.o.retry_ms;
    let mut wait = first;
    let mut told = false;
    loop {
        let mut welcomed = false;
        let why = try_once(&l, &mut welcomed).await;
        l.kept.up.set(false);
        l.kept.relays.borrow_mut().clear();
        if welcomed {
            wait = first;
            told = false;
        }
        if !told {
            say(&l, &format!("registry: lost: {why}; trying again"));
            told = true;
        }
        tokio::time::sleep(duration(wait)).await;
        wait = (wait * 2.0).min(longest);
    }
}

/// The next sealed frame read, if any; Err for one that does not open.
fn next_frame(frames: &mut SealedReader) -> Result<Option<Frame>, &'static str> {
    let f = frames.next();
    if f.is_none() && frames.bad { Err(BAD_FRAME) } else { Ok(f) }
}

/// A message of the registry's, None for one this build does not know.
fn message(f: &Frame) -> Option<FromRegistry> {
    if f.ty != FT_JSON {
        return None;
    }
    serde_json::from_value(Value::Object(read_json(&f.body)?)).ok()
}

/// A started link: its halves, the frames read and the sealer of what it sends.
struct Started {
    r: OwnedReadHalf,
    w: OwnedWriteHalf,
    frames: SealedReader,
    tx: TxSeal,
}

/// The next message from the registry while starting (one of a type not known is an error here).
async fn next_message(
    r: &mut OwnedReadHalf,
    frames: &mut SealedReader,
    buf: &mut [u8],
) -> Result<FromRegistry, String> {
    loop {
        if let Some(f) = next_frame(frames)? {
            return message(&f).ok_or_else(|| BAD_MESSAGE.to_owned());
        }
        match r.read(buf).await {
            Ok(0) => return Err(CLOSED.to_owned()),
            Ok(n) => frames.feed(&buf[..n]),
            Err(_) => return Err(BROKEN.to_owned()),
        }
    }
}

/// The dial and the start: hello, the challenge checked (the registry's signature over the link's own context, by a
/// key whose id is the config's), the prove, the welcome. No prove is sent to a registry whose challenge fails.
async fn start(l: &Link) -> Result<Started, String> {
    let a = parse_address(&l.o.address).ok_or(NO_ADDRESS)?;
    let sock = TcpStream::connect((a.host.as_str(), a.port)).await.map_err(|_| NO_CONNECTION)?;
    let _ = sock.set_nodelay(true);
    let (mut r, mut w) = sock.into_split();
    let raw = l.key.verifying_key().to_bytes();
    let mut nonce = [0u8; NONCE_BYTES];
    rand::fill(&mut nonce);
    let kx = KxSecret::fresh();
    let kx_public = kx.public();
    let hello = ToRegistry::Hello {
        v: REGISTRY_WIRE_VERSION,
        key: STANDARD.encode(raw),
        nonce: STANDARD.encode(nonce),
        kx: STANDARD.encode(kx_public),
    };
    w.write_all(&json_frame(&hello).map_err(|_| BAD_MESSAGE)?).await.map_err(|_| BROKEN)?;
    let mut fr = FrameReader::new();
    let mut buf = vec![0u8; 16 * 1024];
    // (the challenge is the last plain frame: read one frame at a time, so what follows it is read sealed)
    let f = loop {
        if let Some(f) = fr.next() {
            break f;
        }
        if fr.bad {
            return Err(BAD_FRAME.to_owned());
        }
        match r.read(&mut buf).await {
            Ok(0) => return Err(CLOSED.to_owned()),
            Ok(n) => fr.feed(&buf[..n]),
            Err(_) => return Err(BROKEN.to_owned()),
        }
    };
    let (v, key, their_nonce, their_kx, sig) = match message(&f) {
        Some(FromRegistry::Challenge { v, key, nonce, kx, sig }) => (v, key, nonce, kx, sig),
        Some(FromRegistry::Refused { why }) => return Err(refusal(&why)),
        _ => return Err(BAD_MESSAGE.to_owned()),
    };
    if v != REGISTRY_WIRE_VERSION {
        return Err(OTHER_VERSION.to_owned());
    }
    let registry_raw = unb64::<32>(&key).ok_or(BAD_CHALLENGE)?;
    let t = Transcript {
        client_key: raw,
        relay_key: registry_raw,
        client_nonce: nonce,
        relay_nonce: unb64::<NONCE_BYTES>(&their_nonce).ok_or(BAD_CHALLENGE)?,
        client_kx: kx_public,
        relay_kx: unb64::<KX_BYTES>(&their_kx).ok_or(BAD_CHALLENGE)?,
    };
    let sig = Signature::from_bytes(&unb64::<64>(&sig).ok_or(BAD_CHALLENGE)?);
    if bad_public_key(&registry_raw) {
        return Err(BAD_CHALLENGE.to_owned());
    }
    let registry_key = VerifyingKey::from_bytes(&registry_raw).map_err(|_| BAD_CHALLENGE)?;
    if registry_key.verify(&registry_handshake_bytes(Side::Relay, &t), &sig).is_err() {
        return Err(BAD_SIGNATURE.to_owned());
    }
    if key_id(&registry_raw) != l.o.id {
        return Err(OTHER_KEY.to_owned());
    }
    // (a kx of small order: the exchange's secret would be all zero)
    let secret = shared(kx, &t.relay_kx).ok_or(BAD_CHALLENGE)?;
    let (tx, opener, _) = split(&derive(&secret, &t), Side::Client);
    let mut frames = SealedReader::new(opener, fr.take_rest());
    let prove =
        ToRegistry::Prove { sig: STANDARD.encode(l.key.sign(&registry_handshake_bytes(Side::Client, &t)).to_bytes()) };
    w.write_all(&json_frame(&prove).map_err(|_| BAD_MESSAGE)?).await.map_err(|_| BROKEN)?;
    match next_message(&mut r, &mut frames, &mut buf).await? {
        FromRegistry::Welcome { .. } => Ok(Started { r, w, frames, tx }),
        FromRegistry::Refused { why } => Err(refusal(&why)),
        _ => Err(BAD_MESSAGE.to_owned()),
    }
}

/// `m` sealed and written, within `until`.
async fn send(w: &mut OwnedWriteHalf, tx: &mut TxSeal, m: &ToRegistry, until: Instant) -> Result<(), &'static str> {
    let plain = json_frame(m).map_err(|_| BAD_MESSAGE)?;
    let mut out = Vec::new();
    tx.seal_frame(&plain, &mut out).map_err(|_| BAD_MESSAGE)?;
    match timeout_at(until, w.write_all(&out)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(BROKEN),
        Err(_) => Err(QUIET),
    }
}

/// One link from its dial to its end: the start within `start_ms`, then the check-in, a beat every `beat_ms`, and the
/// registry's relays kept, until the registry closes it, refuses it, or sends nothing for `silent_ms`. Why it ended.
async fn try_once(l: &Link, welcomed: &mut bool) -> String {
    let Started { mut r, mut w, mut frames, mut tx } =
        match timeout_at(Instant::now() + duration(l.o.start_ms), start(l)).await {
            Ok(Ok(s)) => s,
            Ok(Err(why)) => return why,
            Err(_) => return SLOW_START.to_owned(),
        };
    *welcomed = true;
    l.kept.up.set(true);
    say(l, "registry: checked in");
    let (beat, silent) = (duration(l.o.beat_ms), duration(l.o.silent_ms));
    let mut heard = Instant::now();
    let check_in = ToRegistry::CheckIn {
        address: l.o.public.clone(),
        wire: RELAY_WIRE_VERSION,
        proto: PROTOCOL,
        counts: (l.counts)(),
    };
    if let Err(why) = send(&mut w, &mut tx, &check_in, heard + silent).await {
        return why.to_owned();
    }
    let mut next_beat = Instant::now() + beat;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        loop {
            let f = match next_frame(&mut frames) {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(why) => return why.to_owned(),
            };
            match message(&f) {
                Some(FromRegistry::RelayUp { relay }) => {
                    l.kept.relays.borrow_mut().insert(relay.id.clone(), relay);
                }
                Some(FromRegistry::RelayGone { id }) => {
                    l.kept.relays.borrow_mut().remove(&id);
                }
                Some(FromRegistry::Refused { why }) => return refusal(&why),
                // (a beat's answer only says the registry is there; a message not known is let pass)
                _ => {}
            }
        }
        let quiet_at = heard + silent;
        match timeout_at(next_beat.min(quiet_at), r.read(&mut buf)).await {
            Ok(Ok(0)) => return CLOSED.to_owned(),
            Ok(Ok(n)) => {
                heard = Instant::now();
                frames.feed(&buf[..n]);
            }
            Ok(Err(_)) => return BROKEN.to_owned(),
            Err(_) => {
                let now = Instant::now();
                if now >= quiet_at {
                    return QUIET.to_owned();
                }
                if now >= next_beat {
                    let b = ToRegistry::Beat { counts: (l.counts)() };
                    if let Err(why) = send(&mut w, &mut tx, &b, quiet_at).await {
                        return why.to_owned();
                    }
                    next_beat = Instant::now() + beat;
                }
            }
        }
    }
}
