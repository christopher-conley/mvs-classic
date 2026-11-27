//! What the web pages add to the registry, kept in a state file beside its config (the config is never written):
//! the approvals and bans made there and the submissions waiting for review; and a submission from the public page,
//! checked and proved before it is approved or kept waiting.

use std::cell::RefCell;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use mvs_protocol::relay_wire::{is_key_id, parse_address};
use mvs_relay::limits::Buckets;
use serde_json::{Map, Value, json};
use tokio::time::Instant;

use crate::core::{Admission, Approved, DENIED, Origin, Registry};
use crate::rules::{Ban, Bans, NO_IPV6, Source, may_dial};
use crate::server::{Handle, Lookup, Prove, Resolve, duration, look_up, prove_key};

/// The state file's fields, and those of an `approved` and a `waiting` entry.
const FIELDS: [&str; 3] = ["approved", "waiting", "bans"];
const APPROVED_FIELDS: [&str; 3] = ["id", "address", "name"];
const WAITING_FIELDS: [&str; 4] = ["id", "address", "name", "since"];
/// A submitted name's most characters.
const NAME_CHARS: usize = 40;

/// What the public page does with a relay it proved: approves it at once, or keeps it waiting for the admin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submissions {
    Auto,
    Review,
}

/// What the pages add, kept in `mvs-registry-state.json` beside the config: approvals and bans made on the admin
/// page, approvals and waiting submissions from the public page. The config is never written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    /// Each of origin Page, with the `ip:port` it was proved at.
    pub approved: Vec<Approved>,
    pub waiting: Vec<Waiting>,
    pub bans: Vec<Ban>,
}

/// A submission proved and kept for the admin's review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiting {
    pub id: String,
    /// The `ip:port` it was proved at.
    pub address: String,
    pub name: Option<String>,
    /// When it was submitted (unix seconds).
    pub since: u64,
}

impl State {
    /// Missing file: empty. A file that does not read stops the program with the reason (never silently empty).
    pub fn load(path: &Path) -> Result<State, String> {
        let f = path.display();
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
            Err(e) => return Err(format!("could not read {f}: {e}")),
        };
        let raw: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
            .map_err(|e| format!("{f} is not JSON: {e}"))?;
        let Value::Object(top) = raw else { return Err(format!("{f} is not a JSON object")) };
        fields(&top, &FIELDS, &f.to_string())?;
        let list = |k: &str| match top.get(k) {
            None => Ok(&[][..]),
            Some(Value::Array(a)) => Ok(&a[..]),
            Some(_) => Err(format!("{f}: {k} is not a list")),
        };
        let mut out = State::default();
        for (i, v) in list("approved")?.iter().enumerate() {
            let e = entry(v, &format!("{f}: approved[{i}]"), &APPROVED_FIELDS)?;
            out.approved.push(Approved { id: e.id, address: Some(e.address), name: e.name, origin: Origin::Page });
        }
        for (i, v) in list("waiting")?.iter().enumerate() {
            let what = format!("{f}: waiting[{i}]");
            let e = entry(v, &what, &WAITING_FIELDS)?;
            let Value::Object(o) = v else { unreachable!("entry read an object") };
            let since = o.get("since").and_then(Value::as_u64).ok_or(format!("{what}.since is not unix seconds"))?;
            out.waiting.push(Waiting { id: e.id, address: e.address, name: e.name, since });
        }
        for (i, v) in list("bans")?.iter().enumerate() {
            let Value::String(t) = v else { return Err(format!("{f}: bans[{i}] is not text")) };
            out.bans.push(Ban::parse(t).map_err(|e| format!("{f}: bans[{i}]: {e}"))?);
        }
        Ok(out)
    }

    /// Written whole to a file beside it and renamed over it.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let entry = |id: &str, address: &str, name: &Option<String>| {
            let mut o = Map::new();
            o.insert("id".into(), json!(id));
            o.insert("address".into(), json!(address));
            if let Some(n) = name {
                o.insert("name".into(), json!(n));
            }
            o
        };
        let approved: Vec<Value> = self
            .approved
            .iter()
            .map(|a| Value::Object(entry(&a.id, a.address.as_deref().unwrap_or_default(), &a.name)))
            .collect();
        let waiting: Vec<Value> = self
            .waiting
            .iter()
            .map(|w| {
                let mut o = entry(&w.id, &w.address, &w.name);
                o.insert("since".into(), json!(w.since));
                Value::Object(o)
            })
            .collect();
        let bans: Vec<Value> = self.bans.iter().map(|b| json!(b.text())).collect();
        let text = serde_json::to_string_pretty(&json!({ "approved": approved, "waiting": waiting, "bans": bans }))
            .map_err(io::Error::other)?;
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        let tmp = path.with_file_name(name);
        if let Err(e) = std::fs::write(&tmp, text + "\n") {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::rename(&tmp, path)
    }
}

/// An error naming the first key of `o` not in `known`.
fn fields(o: &Map<String, Value>, known: &[&str], what: &str) -> Result<(), String> {
    match o.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => Err(format!("{what}: {k} is not a field ({})", known.join(", "))),
        None => Ok(()),
    }
}

/// What an `approved` and a `waiting` entry share.
struct Entry {
    id: String,
    address: String,
    name: Option<String>,
}

fn entry(v: &Value, what: &str, known: &[&str]) -> Result<Entry, String> {
    let Value::Object(o) = v else { return Err(format!("{what} is not an object")) };
    fields(o, known, what)?;
    let id = match o.get("id") {
        Some(Value::String(id)) if is_key_id(id) => id.clone(),
        _ => return Err(format!("{what}.id is not a relay id (r and 32 hex digits)")),
    };
    let address = match o.get("address") {
        Some(Value::String(a)) if parse_address(a).is_some() => a.clone(),
        _ => return Err(format!("{what}.address is not an address (host:port)")),
    };
    let name = match o.get("name") {
        None => None,
        Some(Value::String(n)) => Some(n.clone()),
        Some(_) => return Err(format!("{what}.name is not text")),
    };
    Ok(Entry { id, address, name })
}

/// Who may be listed at the start: the config's approvals and the state's (the config's kept for an id in both),
/// and the bans of both, each once.
pub fn admission(config: Admission, state: &State) -> Admission {
    let mut approved = config.approved;
    for a in &state.approved {
        if !approved.iter().any(|c| c.id == a.id) {
            approved.push(a.clone());
        }
    }
    let mut bans = config.bans;
    for b in &state.bans {
        bans.add(b.clone());
    }
    Admission { mode: config.mode, approved, bans }
}

pub const SUBMIT_RATE: &str = "too many submissions from your address; try again later";
pub const NOT_A_RELAY: &str = "no relay answered at that address";
pub const ALREADY: &str = "that relay is already approved";
pub const BAD_NAME: &str = "that name is not taken";
pub const NOT_AN_ADDRESS: &str = "that is not a relay address (host:port)";

/// What a submission came to: the id proved, approved or waiting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Submitted {
    Approved(String),
    Waiting(String),
}

/// What `submit` works with. It lives on the registry's thread.
pub struct SubmitCx {
    pub registry: Handle,
    pub state: Rc<RefCell<State>>,
    /// The state file.
    pub path: PathBuf,
    /// Submissions by source address.
    pub rates: RefCell<Buckets>,
    /// As `Options::resolve` and `Options::prove` (None: the system's lookup, `prove_key`), and the check's time
    /// (ms): 5000.
    pub resolve: Option<Resolve>,
    pub prove: Option<Prove>,
    pub prove_ms: f64,
    pub mode: Submissions,
}

impl SubmitCx {
    /// The system's lookup and `prove_key`, 5000 ms to check.
    pub fn new(
        registry: Handle,
        state: Rc<RefCell<State>>,
        path: PathBuf,
        submits_per_minute: f64,
        mode: Submissions,
    ) -> SubmitCx {
        SubmitCx {
            registry,
            state,
            path,
            rates: RefCell::new(Buckets::per_minute(submits_per_minute)),
            resolve: None,
            prove: None,
            prove_ms: 5000.0,
            mode,
        }
    }
}

/// A submission from the public page, from `source` at `now` (ms, the clock of the submission rate only). Refused,
/// in this order: past the source's rate (SUBMIT_RATE); a bad name (BAD_NAME); not an address (NOT_AN_ADDRESS); a
/// banned host name (DENIED); a name with no IPv4 answer, or an IPv6 address (NO_IPV6); an address `may_dial` refuses
/// from `Source::Public`; a banned IP (DENIED); a target past its dial rate (SUBMIT_RATE); no relay proved there
/// (NOT_A_RELAY); a banned id (DENIED); an id approved already (ALREADY). Then `Auto` approves it (origin Page, the
/// `ip:port` proved) and `Review` keeps it waiting, and the state is saved (a failed save is logged; the change holds).
/// The name lookup and the dial share the check's time (`prove_ms`, from the lookup's start), and a check that fails
/// is answered at its end whatever the cause, so the answer's time does not tell a closed port from a filtered one.
/// Nothing submitted goes in a log line.
pub async fn submit(
    cx: &SubmitCx,
    source: Ipv4Addr,
    address: &str,
    name: Option<&str>,
    now: f64,
) -> Result<Submitted, &'static str> {
    if !cx.rates.borrow_mut().get(&source.to_string(), now).take(1.0, now) {
        return Err(SUBMIT_RATE);
    }
    let name = read_name(name)?;
    let a = parse_address(address).ok_or(NOT_AN_ADDRESS)?;
    let deadline = Instant::now() + duration(cx.prove_ms);
    let banned = |f: &dyn Fn(&Bans) -> bool| cx.registry.with_core(|r, _| f(&bans_of(r)));
    let ip = match a.host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            if banned(&|b| b.bans_host(&a.host)) {
                return Err(DENIED);
            }
            match look_up(cx.resolve.as_ref(), &a.host, a.port, cx.prove_ms).await {
                Lookup::Ip(ip) => IpAddr::V4(ip),
                Lookup::NoIpv4 => return Err(NO_IPV6),
                Lookup::Failed => return not_a_relay(deadline).await,
            }
        }
    };
    may_dial(ip, Source::Public)?;
    let IpAddr::V4(ip) = ip else { return Err(NO_IPV6) };
    if banned(&|b| b.bans_ip(ip)) {
        return Err(DENIED);
    }
    let at = SocketAddrV4::new(ip, a.port);
    if !cx.registry.with_core(|r, now| r.may_dial_target(at, now)) {
        return Err(SUBMIT_RATE);
    }
    let left = deadline.saturating_duration_since(Instant::now()).as_secs_f64() * 1000.0;
    let dial = match &cx.prove {
        Some(p) => p(at, left),
        None => Box::pin(prove_key(at, left)),
    };
    let Ok(Some(id)) = tokio::time::timeout_at(deadline, dial).await else { return not_a_relay(deadline).await };
    if banned(&|b| b.bans_id(&id)) {
        return Err(DENIED);
    }
    if cx.registry.with_core(|r, _| r.approved().iter().any(|e| e.id == id)) {
        return Err(ALREADY);
    }
    let address = at.to_string();
    let mut st = cx.state.borrow_mut();
    let out = match cx.mode {
        Submissions::Auto => {
            let a = Approved { id: id.clone(), address: Some(address), name, origin: Origin::Page };
            st.waiting.retain(|w| w.id != id);
            match st.approved.iter_mut().find(|e| e.id == id) {
                Some(e) => *e = a.clone(),
                None => st.approved.push(a.clone()),
            }
            cx.registry.with_core(|r, now| r.approve(a, now));
            Submitted::Approved(id)
        }
        Submissions::Review => {
            let since = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let w = Waiting { id: id.clone(), address, name, since };
            match st.waiting.iter_mut().find(|e| e.id == id) {
                Some(e) => *e = w,
                None => st.waiting.push(w),
            }
            Submitted::Waiting(id)
        }
    };
    let saved = st.save(&cx.path);
    drop(st);
    if let Err(e) = saved {
        cx.registry.log(&format!("state: could not save: {e}"));
    }
    Ok(out)
}

/// The registry's bans, to check against.
fn bans_of(r: &Registry) -> Bans {
    Bans::new(r.bans().to_vec())
}

/// NOT_A_RELAY at the check's end.
async fn not_a_relay(deadline: Instant) -> Result<Submitted, &'static str> {
    tokio::time::sleep_until(deadline).await;
    Err(NOT_A_RELAY)
}

/// A submitted name trimmed: None when empty or absent; BAD_NAME past `NAME_CHARS` characters or with a control
/// character.
fn read_name(name: Option<&str>) -> Result<Option<String>, &'static str> {
    let Some(n) = name.map(str::trim).filter(|n| !n.is_empty()) else { return Ok(None) };
    if n.chars().count() > NAME_CHARS || n.chars().any(char::is_control) {
        return Err(BAD_NAME);
    }
    Ok(Some(n.to_string()))
}
