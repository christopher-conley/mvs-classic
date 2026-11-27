//! The registry on a port: a relay's start on the link and what refuses it there, its check-in and the address
//! checks that list it, its beats and its silence, and the checks again of a relay not there yet or that moved.

mod member;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::rc::Rc;

use member::{Member, PROTO, new_key, run, sleep, until};
use mvs_protocol::registry_wire::{REGISTRY_WIRE_VERSION, RelayEntry};
use mvs_protocol::relay_wire::{Side, handshake_bytes, key_id};
use mvs_registry::core::{Admission, Approved, BUSY, DENIED, Limits, Mode, NOT_LISTED, OTHER_ADDRESS, Origin, SILENT};
use mvs_registry::rules::{Ban, Bans, NO_IPV6, NOT_PUBLIC};
use mvs_registry::server::{
    Lookup, NOT_STARTED, Options, Prove, Resolve, Running, STOPPING, prove_key, start_registry,
};
use serde_json::json;

const NAMED: &str = "relay.example";
const AT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const MOVED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);

/// The name lookups and address checks a check answers for the registry, and the checks it was asked for.
#[derive(Clone, Default)]
struct Stub {
    /// Answered in order, for any name; once they are spent, `names`.
    lookups: Rc<RefCell<VecDeque<Lookup>>>,
    /// A name absent here has no IPv4 answer.
    names: Rc<RefCell<HashMap<String, Ipv4Addr>>>,
    /// Answered in order; once they are spent, `id`.
    proves: Rc<RefCell<VecDeque<Option<String>>>>,
    id: Rc<RefCell<Option<String>>>,
    dialed: Rc<RefCell<Vec<SocketAddrV4>>>,
}

impl Stub {
    fn name(&self, host: &str, ip: Ipv4Addr) {
        self.names.borrow_mut().insert(host.to_string(), ip);
    }

    fn answer(&self, id: &str) {
        *self.id.borrow_mut() = Some(id.to_string());
    }

    fn resolve(&self) -> Resolve {
        let (lookups, names) = (self.lookups.clone(), self.names.clone());
        Rc::new(move |host, _port| {
            let next = lookups.borrow_mut().pop_front();
            let found = next.unwrap_or_else(|| names.borrow().get(&host).copied().map_or(Lookup::NoIpv4, Lookup::Ip));
            Box::pin(async move { found })
        })
    }

    fn prove(&self) -> Prove {
        let s = self.clone();
        Rc::new(move |at, _ms| {
            s.dialed.borrow_mut().push(at);
            let next = s.proves.borrow_mut().pop_front();
            let id = next.unwrap_or_else(|| s.id.borrow().clone());
            Box::pin(async move { id })
        })
    }

    fn dialed(&self) -> Vec<SocketAddrV4> {
        self.dialed.borrow().clone()
    }
}

fn open() -> Admission {
    Admission { mode: Mode::Open, approved: Vec::new(), bans: Bans::new(Vec::new()) }
}

/// Options for a check: on 127.0.0.1, port 0, the stub's lookups and checks, every interval in tens of ms.
fn options(stub: &Stub) -> Options {
    Options {
        port: 0,
        host: "127.0.0.1".into(),
        key_file: None,
        admission: open(),
        limits: Limits { recheck_ms: 20.0, refresh_ms: 30.0, ..Limits::default() },
        log: None,
        sweep_ms: 10.0,
        start_ms: 1000.0,
        prove_ms: 200.0,
        resolve: Some(stub.resolve()),
        prove: Some(stub.prove()),
    }
}

fn relays(r: &Running) -> Vec<RelayEntry> {
    r.with_core(|core, _| core.relays(PROTO))
}

fn listed_at(r: &Running, id: &str) -> Option<String> {
    relays(r).into_iter().find(|e| e.id == id).map(|e| e.address)
}

#[test]
fn a_relay_checks_in() {
    run(async {
        let stub = Stub::default();
        stub.name(NAMED, AT);
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        assert_eq!(m.start(&reg.id).await, m.id, "the welcome names the relay's own id");
        m.check_in("relay.example:7777");
        until("listed", 1000, || !relays(&reg).is_empty()).await;
        let entry = RelayEntry { id: m.id.clone(), address: "198.51.100.7:7777".into(), name: None, approved: false };
        assert_eq!(relays(&reg), vec![entry]);
        reg.close().await;
        assert_eq!(m.refused().await, STOPPING);
    });
}

#[test]
fn a_relay_off_the_list_is_refused_at_its_hello() {
    run(async {
        let stub = Stub::default();
        let mut o = options(&stub);
        let other = Approved { id: key_id(&[7; 32]), address: None, name: None, origin: Origin::Config };
        o.admission = Admission { mode: Mode::List, approved: vec![other], bans: Bans::new(Vec::new()) };
        let reg = start_registry(o).unwrap();
        let m = Member::dial(reg.port, None).await;
        m.hello();
        assert_eq!(m.refused().await, NOT_LISTED);
        assert!(!m.saw("challenge"), "refused before any challenge; had {}", m.had());
    });
}

#[test]
fn a_banned_relay_is_refused_at_its_hello() {
    run(async {
        let stub = Stub::default();
        let key = new_key();
        let id = key_id(&key.verifying_key().to_bytes());
        let mut o = options(&stub);
        o.admission.bans = Bans::new(vec![Ban::Id(id)]);
        let reg = start_registry(o).unwrap();
        let m = Member::dial(reg.port, Some(key)).await;
        m.hello();
        assert_eq!(m.refused().await, DENIED);
        assert!(!m.saw("challenge"), "refused before any challenge; had {}", m.had());
    });
}

#[test]
fn one_source_has_its_bound() {
    run(async {
        let stub = Stub::default();
        let mut o = options(&stub);
        o.limits.per_address = 1;
        let reg = start_registry(o).unwrap();
        let first = Member::dial(reg.port, None).await;
        first.start(&reg.id).await;
        let second = Member::dial(reg.port, None).await;
        assert_eq!(second.refused_in(500).await, BUSY, "refused at once, before its hello");
        assert!(!first.closed(), "the first is kept");
    });
}

#[test]
fn another_wire_version_is_refused() {
    run(async {
        let stub = Stub::default();
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        m.hello_v(json!(2));
        assert_eq!(m.refused().await, format!("wire version not {REGISTRY_WIRE_VERSION}"));
        assert!(!m.saw("challenge"));
    });
}

#[test]
fn a_bad_signature_is_refused() {
    run(async {
        let stub = Stub::default();
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        let nonce = m.hello();
        let c = m.msg("challenge").await;
        let t = m.transcript(nonce, &c);
        // (a signature made for the relay wire never passes on this link)
        m.prove_over(&handshake_bytes(Side::Client, &t));
        assert_eq!(m.refused().await, "bad signature");
        assert!(!m.saw("welcome"));
    });
}

#[test]
fn a_start_that_stalls_is_closed() {
    run(async {
        let stub = Stub::default();
        let mut o = options(&stub);
        o.start_ms = 50.0;
        let reg = start_registry(o).unwrap();
        let m = Member::dial(reg.port, None).await;
        assert_eq!(m.refused_in(500).await, NOT_STARTED);
        // (a start that stops after its challenge is held to the same time)
        let m = Member::dial(reg.port, None).await;
        m.hello();
        m.msg("challenge").await;
        assert_eq!(m.refused_in(500).await, NOT_STARTED);
    });
}

#[test]
fn a_beat_is_answered() {
    run(async {
        let stub = Stub::default();
        stub.name(NAMED, AT);
        let mut o = options(&stub);
        o.start_ms = 50.0;
        let reg = start_registry(o).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        m.start(&reg.id).await;
        m.check_in("relay.example:7777");
        // (past the start's time: a started link is not held to it)
        sleep(120).await;
        m.beat();
        m.msg("beat").await;
        assert!(!m.closed());
    });
}

#[test]
fn a_member_that_goes_quiet_is_let_go() {
    run(async {
        let stub = Stub::default();
        stub.name(NAMED, AT);
        let mut o = options(&stub);
        o.limits.silent_ms = 80.0;
        o.sweep_ms = 20.0;
        let reg = start_registry(o).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        m.start(&reg.id).await;
        m.check_in("relay.example:7777");
        assert_eq!(m.refused_in(1000).await, SILENT);
        assert!(relays(&reg).is_empty());
    });
}

#[test]
fn a_name_is_resolved_and_the_answer_dialed() {
    run(async {
        let stub = Stub::default();
        stub.name(NAMED, AT);
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        m.start(&reg.id).await;
        m.check_in("Relay.Example.:7001");
        until("listed", 1000, || listed_at(&reg, &m.id).is_some()).await;
        assert_eq!(stub.dialed(), vec![SocketAddrV4::new(AT, 7001)]);
        assert_eq!(listed_at(&reg, &m.id).as_deref(), Some("198.51.100.7:7001"));
    });
}

#[test]
fn a_name_with_no_ipv4_is_refused() {
    run(async {
        let stub = Stub::default();
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        m.start(&reg.id).await;
        m.check_in("relay.example:7777");
        assert_eq!(m.refused().await, NO_IPV6);
        assert!(stub.dialed().is_empty());
    });
}

#[test]
fn a_failed_lookup_is_tried_again() {
    run(async {
        let stub = Stub::default();
        stub.lookups.borrow_mut().push_back(Lookup::Failed);
        stub.name(NAMED, AT);
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        m.start(&reg.id).await;
        m.check_in("relay.example:7777");
        until("listed", 1000, || listed_at(&reg, &m.id).is_some()).await;
        assert_eq!(listed_at(&reg, &m.id).as_deref(), Some("198.51.100.7:7777"));
        assert_eq!(stub.dialed(), vec![SocketAddrV4::new(AT, 7777)], "no check at the failed lookup");
        assert!(!m.saw("refused") && !m.closed(), "not refused; had {}", m.had());
    });
}

#[test]
fn an_address_that_proves_another_key_is_refused() {
    run(async {
        let file = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("registry-wire-{}.key", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let a = mvs_relay::server::load_key(Some(&file)).unwrap();
        let relay = mvs_relay::server::start_relay(mvs_relay::server::Options {
            host: "127.0.0.1".into(),
            key_file: Some(file.clone()),
            hosted: None,
            ..mvs_relay::server::Options::default()
        })
        .unwrap();
        let _ = std::fs::remove_file(&file);
        let a_id = key_id(&a.verifying_key().to_bytes());
        assert_eq!(relay.id, a_id);
        let b = new_key();
        let b_id = key_id(&b.verifying_key().to_bytes());
        let at = format!("127.0.0.1:{}", relay.port);
        let entry =
            |id: &str| Approved { id: id.into(), address: Some(at.clone()), name: None, origin: Origin::Config };
        let stub = Stub::default();
        let mut o = options(&stub);
        o.admission.approved = vec![entry(&b_id), entry(&a_id)];
        o.prove = None;
        o.prove_ms = 2000.0;
        let reg = start_registry(o).unwrap();

        let mb = Member::dial(reg.port, Some(b)).await;
        mb.start(&reg.id).await;
        mb.check_in(&at);
        assert_eq!(mb.refused().await, OTHER_ADDRESS);
        let there = SocketAddrV4::new(Ipv4Addr::LOCALHOST, relay.port);
        assert_eq!(prove_key(there, 2000.0).await, Some(a_id.clone()), "the relay there is not disturbed");

        let ma = Member::dial(reg.port, Some(a)).await;
        ma.start(&reg.id).await;
        ma.check_in(&at);
        until("A listed", 2000, || listed_at(&reg, &a_id).is_some()).await;
        assert_eq!(listed_at(&reg, &a_id), Some(at.clone()));
        assert_eq!(listed_at(&reg, &b_id), None);
        reg.close().await;
        relay.close().await;
    });
}

#[test]
fn a_loopback_check_in_off_the_config_is_refused() {
    run(async {
        let stub = Stub::default();
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        m.start(&reg.id).await;
        m.check_in("127.0.0.1:7777");
        assert_eq!(m.refused().await, NOT_PUBLIC);
        assert!(stub.dialed().is_empty(), "a refused address is never dialed");
    });
}

#[test]
fn a_relay_not_there_yet_is_checked_again() {
    run(async {
        let stub = Stub::default();
        stub.proves.borrow_mut().extend([None, None]);
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        m.start(&reg.id).await;
        m.check_in("198.51.100.7:7777");
        until("listed", 2000, || listed_at(&reg, &m.id).is_some()).await;
        assert_eq!(stub.dialed(), vec![SocketAddrV4::new(AT, 7777); 3], "listed at the third check");
        assert!(!m.closed());
    });
}

#[test]
fn a_name_that_moves_is_followed() {
    run(async {
        let stub = Stub::default();
        stub.name(NAMED, AT);
        let reg = start_registry(options(&stub)).unwrap();
        let m = Member::dial(reg.port, None).await;
        stub.answer(&m.id);
        m.start(&reg.id).await;
        m.check_in("relay.example:7777");
        until("listed", 1000, || listed_at(&reg, &m.id).is_some()).await;
        assert_eq!(listed_at(&reg, &m.id).as_deref(), Some("198.51.100.7:7777"));
        stub.name(NAMED, MOVED);
        until("moved", 1000, || listed_at(&reg, &m.id).as_deref() == Some("198.51.100.8:7777")).await;
        assert_eq!(stub.dialed().last(), Some(&SocketAddrV4::new(MOVED, 7777)));
        assert!(!m.closed());
    });
}

#[test]
fn a_check_in_past_the_dial_rate_is_tried_later() {
    run(async {
        // (no answer from any check: the stub's id is None)
        let stub = Stub::default();
        let mut o = options(&stub);
        o.limits.dials_per_minute = 1.0;
        let reg = start_registry(o).unwrap();
        let m = Member::dial(reg.port, None).await;
        m.start(&reg.id).await;
        m.check_in("198.51.100.7:7777");
        until("the first check", 1000, || stub.dialed().len() == 1).await;
        // The checks due again at 20, 40 and 80 ms find the target past its rate: no dial, no refusal.
        sleep(200).await;
        assert_eq!(stub.dialed(), [SocketAddrV4::new(AT, 7777)], "one dial within the minute");
        assert_eq!(listed_at(&reg, &m.id), None);
        assert!(!m.closed(), "waiting, not refused");
        reg.close().await;
    });
}
