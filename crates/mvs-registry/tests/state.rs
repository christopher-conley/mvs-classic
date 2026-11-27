//! The public page's submissions (the checks before a relay is dialed, the proof, the rates, what is saved) and the
//! state file the pages' approvals and bans are kept in, with how it meets the config at the start.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mvs_protocol::relay_wire::key_id;
use mvs_registry::core::{Admission, Approved, DENIED, Limits, Mode, Origin};
use mvs_registry::rules::{Ban, Bans, NEVER, NO_IPV6, NOT_PUBLIC};
use mvs_registry::server::{Lookup, Options, Prove, Resolve, Running, start_registry};
use mvs_registry::state::{
    ALREADY, BAD_NAME, NOT_A_RELAY, NOT_AN_ADDRESS, SUBMIT_RATE, State, Submissions, SubmitCx, Submitted, Waiting,
    admission, submit,
};
use serde_json::Value;

/// Runs a check on a current-thread runtime and a `LocalSet`, as the registry runs.
fn run(f: impl Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f);
}

/// A folder of the test's own under the target's temp folder, removed when dropped.
struct Folder(PathBuf);

impl Folder {
    fn new(name: &str) -> Folder {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("state-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Folder(d)
    }

    fn file(&self) -> PathBuf {
        self.0.join("mvs-registry-state.json")
    }

    /// The names of the files in it.
    fn names(&self) -> Vec<String> {
        let mut out: Vec<String> =
            fs::read_dir(&self.0).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        out.sort();
        out
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The name lookups and address checks a check answers, and what was asked of them.
#[derive(Clone, Default)]
struct Stub {
    /// A name absent here has no IPv4 answer.
    names: Rc<RefCell<HashMap<String, Lookup>>>,
    /// The id every address check proves; None for no answer.
    id: Rc<RefCell<Option<String>>>,
    looked_up: Rc<RefCell<Vec<String>>>,
    dialed: Rc<RefCell<Vec<SocketAddrV4>>>,
}

impl Stub {
    fn name(&self, host: &str, l: Lookup) {
        self.names.borrow_mut().insert(host.to_string(), l);
    }

    fn answer(&self, id: Option<String>) {
        *self.id.borrow_mut() = id;
    }

    fn resolve(&self) -> Resolve {
        let s = self.clone();
        Rc::new(move |host, _port| {
            s.looked_up.borrow_mut().push(host.clone());
            let found = s.names.borrow().get(&host).copied().unwrap_or(Lookup::NoIpv4);
            Box::pin(async move { found })
        })
    }

    fn prove(&self) -> Prove {
        let s = self.clone();
        Rc::new(move |at, _ms| {
            s.dialed.borrow_mut().push(at);
            let id = s.id.borrow().clone();
            Box::pin(async move { id })
        })
    }

    fn dialed(&self) -> Vec<SocketAddrV4> {
        self.dialed.borrow().clone()
    }

    fn looked_up(&self) -> Vec<String> {
        self.looked_up.borrow().clone()
    }
}

fn id(n: u8) -> String {
    key_id(&[n; 32])
}

/// A source address of the public page's.
fn source(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, n)
}

fn at(text: &str) -> SocketAddrV4 {
    text.parse().unwrap_or_else(|_| panic!("{text} is an ip:port"))
}

/// An open registry on 127.0.0.1 with these bans and limits.
fn registry(bans: Vec<Ban>, limits: Limits) -> Running {
    start_registry(Options {
        port: 0,
        host: "127.0.0.1".into(),
        admission: Admission { mode: Mode::Open, approved: Vec::new(), bans: Bans::new(bans) },
        limits,
        ..Options::default()
    })
    .unwrap()
}

/// A submission context on `reg` with an empty state saved in `folder`, the stub's lookups and checks, and a check's
/// time of 20 ms.
fn cx(reg: &Running, folder: &Folder, stub: &Stub, mode: Submissions, per_minute: f64) -> SubmitCx {
    let mut cx = SubmitCx::new(reg.handle(), Rc::new(RefCell::new(State::default())), folder.file(), per_minute, mode);
    cx.resolve = Some(stub.resolve());
    cx.prove = Some(stub.prove());
    cx.prove_ms = 20.0;
    cx
}

fn approved(reg: &Running) -> Vec<Approved> {
    reg.with_core(|r, _| r.approved().to_vec())
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn a_public_relay_is_approved_and_saved() {
    let folder = Folder::new("approved");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let reg = registry(vec![], Limits::default());
        let cx = cx(&reg, &folder, &stub, Submissions::Auto, 12.0);
        for bad in ["a\u{7}b", &"n".repeat(41)] {
            assert_eq!(submit(&cx, source(1), "198.51.100.7:7777", Some(bad), 0.0).await, Err(BAD_NAME), "{bad:?}");
        }
        assert_eq!(submit(&cx, source(1), "198.51.100.7:x", None, 0.0).await, Err(NOT_AN_ADDRESS));
        assert!(stub.dialed().is_empty());
        let got = submit(&cx, source(1), "198.51.100.7:7777", Some("  Relay One "), 0.0).await;
        assert_eq!(got, Ok(Submitted::Approved(id(1))));
        let want = Approved {
            id: id(1),
            address: Some("198.51.100.7:7777".into()),
            name: Some("Relay One".into()),
            origin: Origin::Page,
        };
        assert_eq!(approved(&reg), std::slice::from_ref(&want));
        assert_eq!(stub.dialed(), [at("198.51.100.7:7777")]);
        let saved = State::load(&folder.file()).unwrap();
        assert_eq!(saved.approved, [want]);
        assert!(saved.waiting.is_empty() && saved.bans.is_empty());
        assert_eq!(*cx.state.borrow(), saved);
        reg.close().await;
    });
}

#[test]
fn review_mode_keeps_it_waiting() {
    let folder = Folder::new("review");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let reg = registry(vec![], Limits::default());
        let cx = cx(&reg, &folder, &stub, Submissions::Review, 12.0);
        let before = unix_now();
        let got = submit(&cx, source(1), "198.51.100.7", None, 0.0).await;
        assert_eq!(got, Ok(Submitted::Waiting(id(1))));
        assert!(approved(&reg).is_empty());
        let saved = State::load(&folder.file()).unwrap();
        assert!(saved.approved.is_empty());
        let [w] = &saved.waiting[..] else { panic!("one waiting: {:?}", saved.waiting) };
        assert_eq!((&w.id[..], &w.address[..], &w.name), (&id(1)[..], "198.51.100.7:7777", &None));
        assert!((before..=unix_now()).contains(&w.since), "since is unix seconds");
        reg.close().await;
    });
}

#[test]
fn a_private_address_is_refused() {
    let folder = Folder::new("private");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let reg = registry(vec![], Limits::default());
        let cx = cx(&reg, &folder, &stub, Submissions::Auto, 100.0);
        for ip in ["10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1", "127.0.0.1"] {
            assert_eq!(submit(&cx, source(1), &format!("{ip}:7777"), None, 0.0).await, Err(NOT_PUBLIC), "{ip}");
        }
        assert!(stub.dialed().is_empty(), "never dialed");
        assert!(approved(&reg).is_empty());
        reg.close().await;
    });
}

#[test]
fn never_and_ipv6_are_refused() {
    let folder = Folder::new("never");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        stub.name("six.example", Lookup::NoIpv4);
        let reg = registry(vec![], Limits::default());
        let cx = cx(&reg, &folder, &stub, Submissions::Auto, 100.0);
        for a in ["0.1.2.3:7777", "169.254.1.1:7777", "224.0.0.1:7777", "240.0.0.1:7777", "255.255.255.255:7777"] {
            assert_eq!(submit(&cx, source(1), a, None, 0.0).await, Err(NEVER), "{a}");
        }
        for a in ["[2001:db8::1]:7777", "2001:db8::1", "[::ffff:198.51.100.7]:7777", "six.example:7777"] {
            assert_eq!(submit(&cx, source(1), a, None, 0.0).await, Err(NO_IPV6), "{a}");
        }
        assert!(stub.dialed().is_empty(), "never dialed");
        reg.close().await;
    });
}

#[test]
fn a_name_is_resolved_first() {
    let folder = Folder::new("name");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        stub.name("home.example", Lookup::Ip(Ipv4Addr::new(10, 0, 0, 5)));
        stub.name("relay.example", Lookup::Ip(Ipv4Addr::new(198, 51, 100, 9)));
        let reg = registry(vec![], Limits::default());
        let cx = cx(&reg, &folder, &stub, Submissions::Auto, 12.0);
        assert_eq!(submit(&cx, source(1), "home.example:7777", None, 0.0).await, Err(NOT_PUBLIC));
        assert!(stub.dialed().is_empty());
        assert_eq!(submit(&cx, source(1), "relay.example:7777", None, 0.0).await, Ok(Submitted::Approved(id(1))));
        assert_eq!(stub.dialed(), [at("198.51.100.9:7777")], "the answer dialed");
        assert_eq!(approved(&reg)[0].address.as_deref(), Some("198.51.100.9:7777"), "listed at the address proved");
        reg.close().await;
    });
}

#[test]
fn banned_ones_are_refused() {
    let folder = Folder::new("banned");
    run(async {
        let stub = Stub::default();
        stub.name("banned.example", Lookup::Ip(Ipv4Addr::new(198, 51, 100, 50)));
        let bans = vec![
            Ban::Host("banned.example".into()),
            Ban::Range(Ipv4Addr::new(198, 51, 100, 10), Ipv4Addr::new(198, 51, 100, 20)),
            Ban::Id(id(3)),
        ];
        let reg = registry(bans, Limits::default());
        let cx = cx(&reg, &folder, &stub, Submissions::Auto, 100.0);
        stub.answer(Some(id(1)));
        for a in ["banned.example:7777", "Banned.Example.:7777"] {
            assert_eq!(submit(&cx, source(1), a, None, 0.0).await, Err(DENIED), "{a}");
        }
        assert!(stub.looked_up().is_empty(), "a banned name is not looked up");
        assert_eq!(submit(&cx, source(1), "198.51.100.15:7777", None, 0.0).await, Err(DENIED));
        assert!(stub.dialed().is_empty(), "a banned name or IP is never dialed");
        stub.answer(Some(id(3)));
        assert_eq!(submit(&cx, source(1), "198.51.100.30:7777", None, 0.0).await, Err(DENIED));
        assert_eq!(stub.dialed(), [at("198.51.100.30:7777")], "the id is known once proved");
        assert!(approved(&reg).is_empty());
        assert!(!folder.file().exists(), "nothing saved");
        reg.close().await;
    });
}

#[test]
fn no_relay_there_is_named() {
    let folder = Folder::new("none");
    run(async {
        let stub = Stub::default();
        stub.name("gone.example", Lookup::Failed);
        let reg = registry(vec![], Limits::default());
        let cx = cx(&reg, &folder, &stub, Submissions::Auto, 12.0);
        assert_eq!(submit(&cx, source(1), "198.51.100.7:7777", None, 0.0).await, Err(NOT_A_RELAY));
        assert_eq!(submit(&cx, source(1), "gone.example:7777", None, 0.0).await, Err(NOT_A_RELAY), "no lookup");
        assert_eq!(stub.dialed(), [at("198.51.100.7:7777")]);
        assert!(approved(&reg).is_empty());
        reg.close().await;
    });
}

#[test]
fn submissions_have_a_rate() {
    let folder = Folder::new("rate");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let reg = registry(vec![], Limits::default());
        let cx = cx(&reg, &folder, &stub, Submissions::Auto, 2.0);
        assert_eq!(submit(&cx, source(1), "198.51.100.1:7777", None, 0.0).await, Ok(Submitted::Approved(id(1))));
        assert_eq!(submit(&cx, source(1), "198.51.100.2:7777", None, 1.0).await, Err(ALREADY));
        assert_eq!(submit(&cx, source(1), "198.51.100.3:7777", None, 2.0).await, Err(SUBMIT_RATE), "the third");
        assert_eq!(stub.dialed().len(), 2, "the third is not dialed");
        assert_eq!(submit(&cx, source(2), "198.51.100.3:7777", None, 2.0).await, Err(ALREADY), "another source");
        assert_eq!(submit(&cx, source(1), "198.51.100.4:7777", None, 60_002.0).await, Err(ALREADY), "a minute on");
        assert_eq!(stub.dialed().len(), 4);
        reg.close().await;
    });
}

#[test]
fn one_target_has_its_rate() {
    let folder = Folder::new("target");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let reg = registry(vec![], Limits { dials_per_minute: 2.0, ..Limits::default() });
        let cx = cx(&reg, &folder, &stub, Submissions::Auto, 12.0);
        let a = "198.51.100.7:7777";
        assert_eq!(submit(&cx, source(1), a, None, 0.0).await, Ok(Submitted::Approved(id(1))));
        assert_eq!(submit(&cx, source(2), a, None, 0.0).await, Err(ALREADY));
        assert_eq!(submit(&cx, source(3), a, None, 0.0).await, Err(SUBMIT_RATE), "the third dial of one target");
        assert_eq!(stub.dialed().len(), 2, "the third is not dialed");
        assert_eq!(submit(&cx, source(3), "198.51.100.7:7778", None, 0.0).await, Err(ALREADY), "another target");
        reg.close().await;
    });
}

#[test]
fn a_failed_check_takes_the_full_time() {
    let folder = Folder::new("time");
    run(async {
        let stub = Stub::default();
        stub.name("gone.example", Lookup::Failed);
        let reg = registry(vec![], Limits::default());
        let mut cx = cx(&reg, &folder, &stub, Submissions::Auto, 12.0);
        cx.prove_ms = 100.0;
        for a in ["198.51.100.7:7777", "gone.example:7777"] {
            let t = Instant::now();
            assert_eq!(submit(&cx, source(1), a, None, 0.0).await, Err(NOT_A_RELAY), "{a}");
            assert!(t.elapsed() >= Duration::from_millis(100), "{a}: answered after {:?}", t.elapsed());
        }
        reg.close().await;
    });
}

#[test]
fn a_bad_state_file_is_named() {
    let folder = Folder::new("bad");
    let file = folder.file();
    assert_eq!(State::load(&file), Ok(State::default()), "a missing file is empty");
    let shown = file.display().to_string();
    let bad = [
        "not json",
        "[]",
        r#"{"approved": [], "waiting": [], "bans": [], "other": 1}"#,
        r#"{"bans": ["1.2.3"]}"#,
        r#"{"approved": [{"id": "r1", "address": "198.51.100.7:7777"}]}"#,
        r#"{"waiting": [{"id": "IDHERE", "address": "198.51.100.7:7777"}]}"#,
    ];
    for text in bad {
        let text = text.replace("IDHERE", &id(1));
        fs::write(&file, &text).unwrap();
        let e = State::load(&file).expect_err(&text);
        assert!(e.contains(&shown), "{text}: {e} names the file");
    }
}

#[test]
fn the_save_replaces_the_file_whole() {
    let folder = Folder::new("save");
    let file = folder.file();
    let page = |n: u8| Approved {
        id: id(n),
        address: Some(format!("198.51.100.{n}:7777")),
        name: Some(format!("Relay {n}")),
        origin: Origin::Page,
    };
    let first = State {
        approved: vec![page(1), page(2)],
        waiting: vec![],
        bans: vec![Ban::Cidr(Ipv4Addr::new(10, 18, 18, 0), 27), Ban::Host("bad.example".into())],
    };
    first.save(&file).unwrap();
    let raw: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(raw["approved"][1]["address"], "198.51.100.2:7777");
    assert_eq!(raw["bans"], serde_json::json!(["10.18.18.0/27", "bad.example"]));
    assert_eq!(State::load(&file), Ok(first));
    let second = State {
        approved: vec![],
        waiting: vec![Waiting { id: id(3), address: "198.51.100.3:7777".into(), name: None, since: 1_800_000_000 }],
        bans: vec![],
    };
    second.save(&file).unwrap();
    assert_eq!(State::load(&file), Ok(second));
    assert_eq!(folder.names(), ["mvs-registry-state.json"], "no temporary file is left");
}

#[test]
fn config_and_state_meet_at_start() {
    let from_config = Approved {
        id: id(1),
        address: Some("10.0.0.5:7777".into()),
        name: Some("From config".into()),
        origin: Origin::Config,
    };
    let config = Admission {
        mode: Mode::List,
        approved: vec![from_config.clone()],
        bans: Bans::new(vec![Ban::Ip(Ipv4Addr::new(198, 51, 100, 1))]),
    };
    let page =
        |n: u8| Approved { id: id(n), address: Some(format!("198.51.100.{n}:7777")), name: None, origin: Origin::Page };
    let state = State {
        approved: vec![page(1), page(2)],
        waiting: vec![Waiting { id: id(4), address: "198.51.100.4:7777".into(), name: None, since: 1 }],
        bans: vec![Ban::Ip(Ipv4Addr::new(198, 51, 100, 1)), Ban::Id(id(9))],
    };
    let a = admission(config, &state);
    assert_eq!(a.mode, Mode::List);
    assert_eq!(a.approved, [from_config, page(2)], "the config's kept for an id in both");
    assert_eq!(a.bans.list(), [Ban::Ip(Ipv4Addr::new(198, 51, 100, 1)), Ban::Id(id(9))], "each once");
}
