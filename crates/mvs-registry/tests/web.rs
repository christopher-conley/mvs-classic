//! The registry's two web pages, over real sockets: the public form and its submissions, the admin page's token and
//! form field, its changes to the registry and the state file, the escaping of what is shown, and the body limit.

use std::cell::RefCell;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::rc::Rc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mvs_protocol::registry_wire::{Counts, FromRegistry};
use mvs_protocol::relay_wire::{RELAY_WIRE_VERSION, key_id};
use mvs_registry::core::{Admission, Approved, DENIED, Member, Mode, Origin, Proof, Registry};
use mvs_registry::rules::{Ban, Bans, NOT_PUBLIC};
use mvs_registry::server::{Lookup, Options, Prove, Resolve, Running, start_registry};
use mvs_registry::state::{NOT_AN_ADDRESS, State, Submissions, SubmitCx};
use mvs_registry::web::{PageOptions, Pages, start_pages};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TOKEN: &str = "t0ken-for-the-tests";
const PROTO: u32 = 33;

/// Runs a check on a current-thread runtime and a `LocalSet`, as the registry runs.
fn run(f: impl Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f);
}

/// A folder of the test's own under the target's temp folder, removed when dropped.
struct Folder(PathBuf);

impl Folder {
    fn new(name: &str) -> Folder {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("web-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Folder(d)
    }

    fn file(&self) -> PathBuf {
        self.0.join("mvs-registry-state.json")
    }

    /// The state file's bytes; None when there is none.
    fn bytes(&self) -> Option<Vec<u8>> {
        fs::read(self.file()).ok()
    }

    fn saved(&self) -> State {
        State::load(&self.file()).unwrap()
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The address checks a test answers (every one proves `id`; None for no answer), and what was dialed.
#[derive(Clone, Default)]
struct Stub {
    id: Rc<RefCell<Option<String>>>,
    dialed: Rc<RefCell<Vec<SocketAddrV4>>>,
}

impl Stub {
    fn answer(&self, id: Option<String>) {
        *self.id.borrow_mut() = id;
    }

    fn resolve(&self) -> Resolve {
        Rc::new(move |_host, _port| Box::pin(async { Lookup::NoIpv4 }))
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
}

/// A member the test lists by hand, and the refusals it was sent.
#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Vec<String>>>);

impl Member for Fake {
    fn send(&mut self, _m: &FromRegistry) -> bool {
        true
    }
    fn refuse(&mut self, why: &str) {
        self.0.borrow_mut().push(why.to_string());
    }
}

impl Fake {
    fn refused(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

type Log = Rc<RefCell<Vec<String>>>;

fn id(n: u8) -> String {
    key_id(&[n; 32])
}

fn source(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, n)
}

fn counts() -> Counts {
    Counts { players: 1, max_players: 500, matches: 0, max_matches: 250 }
}

/// A member from `from`, as `id(n)`, checked in at `address` (looked up to `ip`) and listed there.
fn list(r: &mut Registry, n: u8, from: Ipv4Addr, address: &str, ip: Ipv4Addr, now: f64) -> Fake {
    let f = Fake::default();
    let k = r.connect(from, Box::new(f.clone()), now).expect("connected");
    r.hello(k, &id(n), now).expect("hello taken");
    r.proved(k, now);
    r.check_in(k, address, RELAY_WIRE_VERSION, PROTO, counts(), now).expect("checked in");
    r.resolved(k, ip, now).expect("an address to check");
    r.verified(k, Proof::Proved, now);
    assert!(r.seen().iter().any(|s| s.id.as_deref() == Some(&id(n)[..]) && s.listed), "{n} listed");
    f
}

/// A registry and its pages on 127.0.0.1, ports picked: an open registry with the config's approvals and bans, an
/// empty state saved in the folder, the stub's checks (20 ms), and a submission rate no test reaches.
struct Setup {
    reg: Running,
    pages: Pages,
    log: Log,
}

impl Setup {
    fn new(
        folder: &Folder,
        stub: &Stub,
        mode: Submissions,
        token: &str,
        config: Vec<Approved>,
        bans: Vec<Ban>,
    ) -> Setup {
        let log = Log::default();
        let to = log.clone();
        let reg = start_registry(Options {
            port: 0,
            host: "127.0.0.1".into(),
            admission: Admission { mode: Mode::Open, approved: config, bans: Bans::new(bans) },
            log: Some(Box::new(move |l: &str| to.borrow_mut().push(l.to_string()))),
            ..Options::default()
        })
        .unwrap();
        let state = Rc::new(RefCell::new(State::default()));
        let mut cx = SubmitCx::new(reg.handle(), state, folder.file(), 1000.0, mode);
        cx.resolve = Some(stub.resolve());
        cx.prove = Some(stub.prove());
        cx.prove_ms = 20.0;
        let o = PageOptions {
            port: 0,
            host: "127.0.0.1".into(),
            admin_port: 0,
            admin_host: "127.0.0.1".into(),
            admin_token: token.into(),
        };
        let pages = start_pages(o, cx).unwrap();
        Setup { reg, pages, log }
    }

    fn admin(&self) -> u16 {
        self.pages.admin_port.expect("the admin page is on")
    }

    fn approved(&self) -> Vec<Approved> {
        self.reg.with_core(|r, _| r.approved().to_vec())
    }

    fn bans(&self) -> Vec<Ban> {
        self.reg.with_core(|r, _| r.bans().to_vec())
    }

    fn lines(&self) -> Vec<String> {
        self.log.borrow().clone()
    }

    async fn close(self) {
        drop(self.pages);
        self.reg.close().await;
    }
}

/// An HTTP answer: its status, its head (lowercase) and its body.
struct Reply {
    status: u16,
    head: String,
    body: String,
}

/// One request written by hand (HTTP/1.1, `Connection: close`), read to its end. `auth` is `user:password` for HTTP
/// Basic; a POST's body is form-encoded.
async fn http(port: u16, method: &str, path: &str, auth: Option<&str>, body: &str) -> Reply {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(a) = auth {
        req += &format!("Authorization: Basic {}\r\n", STANDARD.encode(a));
    }
    if method == "POST" {
        req += &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n", body.len());
    }
    req += "\r\n";
    req += body;
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or_else(|| panic!("a status: {head}"));
    Reply { status, head: head.to_ascii_lowercase(), body: body.to_string() }
}

fn get(port: u16, auth: Option<&str>) -> impl Future<Output = Reply> {
    http(port, "GET", "/", auth, "")
}

/// A form's body, every byte but a letter or digit percent-encoded.
fn form(pairs: &[(&str, &str)]) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") })
            .collect::<String>()
    };
    pairs.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

/// An admin page's POST with the right token, its form carrying `form` (None: no such field).
async fn admin_post(port: u16, path: &str, form_field: Option<&str>, pairs: &[(&str, &str)]) -> Reply {
    let mut all: Vec<(&str, &str)> = pairs.to_vec();
    if let Some(f) = form_field {
        all.push(("form", f));
    }
    http(port, "POST", path, Some(&format!("admin:{TOKEN}")), &form(&all)).await
}

/// HTML's escape of a text, as the pages must write it.
fn escaped(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

#[test]
fn the_form_is_served() {
    let folder = Folder::new("form");
    run(async {
        let s = Setup::new(&folder, &Stub::default(), Submissions::Auto, TOKEN, vec![], vec![]);
        let r = get(s.pages.port, None).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.head.contains("content-type: text/html"), "{}", r.head);
        for want in [r#"<form method="post" action="/submit">"#, r#"name="address""#, r#"name="name""#] {
            assert!(r.body.contains(want), "{want} in {}", r.body);
        }
        assert!(!r.body.contains("<script") && !r.body.contains("://"), "no script, no outside asset");
        let lines = s.lines();
        let (p, a) = (s.pages.port, s.admin());
        assert!(lines.contains(&format!("public page on 127.0.0.1:{p}")), "{lines:?}");
        assert!(lines.contains(&format!("admin page on 127.0.0.1:{a}")), "{lines:?}");
        assert!(lines.iter().all(|l| !l.contains(TOKEN)), "{lines:?}");
        assert_eq!(http(p, "GET", "/nothing", None, "").await.status, 404);
        s.close().await;
    });
}

#[test]
fn a_submission_is_approved() {
    let folder = Folder::new("approved");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let s = Setup::new(&folder, &stub, Submissions::Auto, TOKEN, vec![], vec![]);
        let p = s.pages.port;
        let r =
            http(p, "POST", "/submit", None, &form(&[("address", "198.51.100.7:7777"), ("name", "Relay One")])).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains(&id(1)) && r.body.contains("approved"), "{}", r.body);
        assert!(r.body.contains("198.51.100.7:7777"), "{}", r.body);
        assert!(!r.body.contains("Relay One"), "the name is not echoed: {}", r.body);
        assert_eq!(stub.dialed(), ["198.51.100.7:7777".parse::<SocketAddrV4>().unwrap()]);
        let want = Approved {
            id: id(1),
            address: Some("198.51.100.7:7777".into()),
            name: Some("Relay One".into()),
            origin: Origin::Page,
        };
        assert_eq!(s.approved(), std::slice::from_ref(&want));
        assert_eq!(folder.saved().approved, [want]);
        // approved, but not checked in: not on the page yet
        assert!(!get(p, None).await.body.contains(&id(1)));
        let _f =
            s.reg.with_core(|r, now| list(r, 1, source(1), "198.51.100.7:7777", Ipv4Addr::new(198, 51, 100, 7), now));
        let page = get(p, None).await;
        assert_eq!(page.status, 200);
        for want in ["Relay One", "198.51.100.7:7777", &id(1)] {
            assert!(page.body.contains(want), "{want} in {}", page.body);
        }
        assert!(s.lines().iter().all(|l| !l.contains("Relay One")), "{:?}", s.lines());
        s.close().await;
    });
}

#[test]
fn a_private_submission_is_refused_with_its_reason() {
    let folder = Folder::new("private");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let s = Setup::new(&folder, &stub, Submissions::Auto, TOKEN, vec![], vec![]);
        let p = s.pages.port;
        let r = http(p, "POST", "/submit", None, &form(&[("address", "10.0.0.5:7777")])).await;
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body.contains(&escaped(NOT_PUBLIC)), "{}", r.body);
        assert!(r.body.contains("10.0.0.5:7777"), "the address read back: {}", r.body);
        let r = http(p, "POST", "/submit", None, &form(&[("address", "<i>&:1")])).await;
        assert!(r.body.contains(&escaped(NOT_AN_ADDRESS)), "{}", r.body);
        assert!(r.body.contains("&lt;i&gt;&amp;:1") && !r.body.contains("<i>"), "escaped: {}", r.body);
        assert!(stub.dialed().is_empty());
        assert!(s.approved().is_empty());
        assert!(folder.bytes().is_none(), "nothing saved");
        s.close().await;
    });
}

#[test]
fn the_admin_page_needs_the_token() {
    let folder = Folder::new("token");
    run(async {
        let s = Setup::new(&folder, &Stub::default(), Submissions::Auto, TOKEN, vec![], vec![]);
        let a = s.admin();
        let same_length = "x".repeat(TOKEN.len());
        let longer = format!("admin:{TOKEN}x");
        let shorter = format!("admin:{}", &TOKEN[..TOKEN.len() - 1]);
        let wrong = format!("admin:{same_length}");
        let as_user = format!("{TOKEN}:{same_length}");
        // the token's length, one byte off: the first, then the last
        let first = format!("admin:X{}", &TOKEN[1..]);
        let last = format!("admin:{}X", &TOKEN[..TOKEN.len() - 1]);
        let wrong_ones = [&wrong, &longer, &shorter, &as_user, &first, &last];
        for auth in [None, Some("nocolon")].into_iter().chain(wrong_ones.iter().map(|w| Some(&w[..]))) {
            let r = get(a, auth).await;
            assert_eq!(r.status, 401, "{auth:?}");
            assert!(r.head.contains("\r\nwww-authenticate: basic realm=\"mvs-registry\""), "{}", r.head);
        }
        for user in ["admin", "", "anyone at all"] {
            let r = get(a, Some(&format!("{user}:{TOKEN}"))).await;
            assert_eq!(r.status, 200, "{user:?}: {}", r.body);
        }
        let ban = form(&[("ban", &id(9)), ("form", TOKEN)]);
        assert_eq!(http(a, "POST", "/ban", None, &ban).await.status, 401);
        assert_eq!(http(a, "POST", "/ban", Some(&wrong), &ban).await.status, 401);
        assert!(s.bans().is_empty());
        assert!(folder.bytes().is_none());
        s.close().await;
    });
}

#[test]
fn the_admin_page_is_off_without_a_token() {
    let folder = Folder::new("off");
    run(async {
        let s = Setup::new(&folder, &Stub::default(), Submissions::Auto, "", vec![], vec![]);
        assert_eq!(s.pages.admin_port, None);
        let lines = s.lines();
        assert!(lines.iter().any(|l| l == "admin page off (no adminToken)"), "{lines:?}");
        assert!(lines.iter().all(|l| !l.starts_with("admin page on")), "{lines:?}");
        assert_eq!(get(s.pages.port, None).await.status, 200);
        s.close().await;
    });
}

#[test]
fn an_admin_post_needs_the_form_field() {
    let folder = Folder::new("field");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let s = Setup::new(&folder, &stub, Submissions::Review, TOKEN, vec![], vec![]);
        let (p, a) = (s.pages.port, s.admin());
        let r = http(p, "POST", "/submit", None, &form(&[("address", "198.51.100.7:7777")])).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains(&id(1)) && r.body.contains("waiting for the registry&#39;s owner"), "{}", r.body);
        let before = folder.bytes().expect("the waiting one saved");
        assert_eq!(folder.saved().waiting.len(), 1);
        let page = get(a, Some(&format!("x:{TOKEN}"))).await;
        assert!(page.body.contains(&id(1)), "the waiting one listed: {}", page.body);
        let wrong = "y".repeat(TOKEN.len());
        // the token's length, its first byte off
        let first = format!("X{}", &TOKEN[1..]);
        for field in [None, Some(&wrong[..]), Some(""), Some(&TOKEN[1..]), Some(&first[..])] {
            let r = admin_post(a, "/approve", field, &[("id", &id(1))]).await;
            assert_eq!(r.status, 403, "{field:?}");
            let r = admin_post(a, "/ban", field, &[("ban", "198.51.100.0/24")]).await;
            assert_eq!(r.status, 403, "{field:?}");
        }
        assert!(s.approved().is_empty() && s.bans().is_empty());
        assert_eq!(folder.bytes().as_ref(), Some(&before), "the state file unchanged");
        let r = admin_post(a, "/approve", Some(TOKEN), &[("id", &id(1))]).await;
        assert_eq!(r.status, 303, "{}", r.body);
        assert!(r.head.contains("\r\nlocation: /"), "{}", r.head);
        let want = Approved { id: id(1), address: Some("198.51.100.7:7777".into()), name: None, origin: Origin::Page };
        assert_eq!(s.approved(), std::slice::from_ref(&want));
        let saved = folder.saved();
        assert_eq!(saved.approved, [want]);
        assert!(saved.waiting.is_empty());
        assert_eq!(admin_post(a, "/approve", Some(TOKEN), &[("id", &id(1))]).await.status, 400, "no longer waiting");
        assert!(s.lines().iter().all(|l| !l.contains(TOKEN)), "{:?}", s.lines());
        s.close().await;
    });
}

#[test]
fn a_ban_from_the_admin_page_lets_a_relay_go() {
    let folder = Folder::new("ban");
    run(async {
        let s = Setup::new(&folder, &Stub::default(), Submissions::Auto, TOKEN, vec![], vec![]);
        let a = s.admin();
        let v4 = |t: &str| t.parse::<Ipv4Addr>().unwrap();
        // each held by one of the five forms: its id, its source IP, a range over its listed IP, a block over it,
        // the host name it checked in with
        let members = s.reg.with_core(|r, now| {
            [
                list(r, 1, source(1), "198.51.100.1:7777", v4("198.51.100.1"), now),
                list(r, 2, source(2), "198.51.100.2:7777", v4("198.51.100.2"), now),
                list(r, 3, source(3), "198.51.100.3:7777", v4("198.51.100.3"), now),
                list(r, 4, source(4), "192.0.2.9:7777", v4("192.0.2.9"), now),
                list(r, 5, source(5), "Relay5.Example:7777", v4("198.51.100.5"), now),
            ]
        });
        let page = get(a, Some(&format!("x:{TOKEN}"))).await;
        for n in 1..=5 {
            assert!(page.body.contains(&format!(r#"name="ban" value="{}""#, id(n))), "a ban-its-id button for {n}");
            assert!(page.body.contains(&format!(r#"name="ban" value="{}""#, source(n))), "a ban-its-IP button for {n}");
        }
        let texts = [
            id(1),
            "203.0.113.2".into(),
            "198.51.100.3 - 198.51.100.3".into(),
            "192.0.2.8/29".into(),
            "relay5.example.".into(),
        ];
        let want = [
            Ban::Id(id(1)),
            Ban::Ip(source(2)),
            Ban::Range(v4("198.51.100.3"), v4("198.51.100.3")),
            Ban::Cidr(v4("192.0.2.8"), 29),
            Ban::Host("relay5.example".into()),
        ];
        for (i, t) in texts.iter().enumerate() {
            let r = admin_post(a, "/ban", Some(TOKEN), &[("ban", t)]).await;
            assert_eq!(r.status, 303, "{t}: {}", r.body);
            for (j, m) in members.iter().enumerate() {
                let want: Vec<String> = if j <= i { vec![DENIED.into()] } else { vec![] };
                assert_eq!(m.refused(), want, "member {} after ban {t}", j + 1);
            }
        }
        assert_eq!(s.bans(), want);
        assert_eq!(folder.saved().bans, want);
        let page = get(a, Some(&format!("x:{TOKEN}"))).await;
        assert!(page.body.contains("192.0.2.8/29") && page.body.contains("from the page"), "{}", page.body);
        // a parse error is shown, escaped; nothing changes
        let r = admin_post(a, "/ban", Some(TOKEN), &[("ban", "<b>.example")]).await;
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body.contains("&lt;b&gt;.example") && !r.body.contains("<b>"), "{}", r.body);
        assert!(r.body.contains("not a relay id, an IPv4 address, a range, a block or a host name"), "{}", r.body);
        assert_eq!(s.bans(), want);
        // a page ban is lifted
        let r = admin_post(a, "/unban", Some(TOKEN), &[("ban", "192.0.2.8/29")]).await;
        assert_eq!(r.status, 303, "{}", r.body);
        assert!(!s.bans().contains(&want[3]));
        assert!(!folder.saved().bans.contains(&want[3]));
        assert_eq!(admin_post(a, "/unban", Some(TOKEN), &[("ban", "192.0.2.8/29")]).await.status, 400, "gone");
        let lines = s.lines();
        for posted in [TOKEN, "relay5.example.", "<b>.example", "198.51.100.3 - "] {
            assert!(lines.iter().all(|l| !l.contains(posted)), "{posted} in {lines:?}");
        }
        s.close().await;
    });
}

#[test]
fn a_config_entry_cannot_be_removed() {
    let folder = Folder::new("config");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(3)));
        let config = Approved { id: id(2), address: Some("10.0.0.2:7777".into()), name: None, origin: Origin::Config };
        let config_ban = Ban::Ip("198.51.100.200".parse().unwrap());
        let s = Setup::new(&folder, &stub, Submissions::Auto, TOKEN, vec![config.clone()], vec![config_ban.clone()]);
        let (p, a) = (s.pages.port, s.admin());
        let page = get(a, Some(&format!("x:{TOKEN}"))).await;
        assert!(page.body.contains(&id(2)) && page.body.contains("from config"), "{}", page.body);
        assert!(page.body.contains("198.51.100.200"), "{}", page.body);
        let r = admin_post(a, "/remove", Some(TOKEN), &[("id", &id(2))]).await;
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body.contains("edit the config to remove this one"), "{}", r.body);
        let r = admin_post(a, "/unban", Some(TOKEN), &[("ban", "198.51.100.200")]).await;
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body.contains("edit the config to remove this one"), "{}", r.body);
        assert_eq!(s.approved(), std::slice::from_ref(&config));
        assert_eq!(s.bans(), std::slice::from_ref(&config_ban));
        assert!(folder.bytes().is_none(), "nothing saved");
        // a page approval is removed
        let r = http(p, "POST", "/submit", None, &form(&[("address", "198.51.100.3:7777")])).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(s.approved().len(), 2);
        let r = admin_post(a, "/remove", Some(TOKEN), &[("id", &id(3))]).await;
        assert_eq!(r.status, 303, "{}", r.body);
        assert_eq!(s.approved(), [config]);
        assert!(folder.saved().approved.is_empty());
        assert_eq!(admin_post(a, "/remove", Some(TOKEN), &[("id", &id(3))]).await.status, 400, "no longer approved");
        s.close().await;
    });
}

#[test]
fn names_are_escaped() {
    let folder = Folder::new("escaped");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let s = Setup::new(&folder, &stub, Submissions::Auto, TOKEN, vec![], vec![]);
        let (p, a) = (s.pages.port, s.admin());
        let name = r#"<b>"x'&</b>"#;
        let r = http(p, "POST", "/submit", None, &form(&[("address", "198.51.100.7:7777"), ("name", name)])).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let _f =
            s.reg.with_core(|r, now| list(r, 1, source(1), "198.51.100.7:7777", Ipv4Addr::new(198, 51, 100, 7), now));
        let want = "&lt;b&gt;&quot;x&#39;&amp;&lt;/b&gt;";
        for page in [get(p, None).await, get(a, Some(&format!("x:{TOKEN}"))).await] {
            assert_eq!(page.status, 200);
            assert!(page.body.contains(want), "{want} in {}", page.body);
            assert!(!page.body.contains("<b>") && !page.body.contains(name), "{}", page.body);
        }
        assert!(s.lines().iter().all(|l| !l.contains("<b>")), "{:?}", s.lines());
        s.close().await;
    });
}

#[test]
fn a_large_body_is_refused() {
    let folder = Folder::new("large");
    run(async {
        let stub = Stub::default();
        stub.answer(Some(id(1)));
        let s = Setup::new(&folder, &stub, Submissions::Auto, TOKEN, vec![], vec![]);
        let (p, a) = (s.pages.port, s.admin());
        let big = format!("address=198.51.100.7:7777&name={}", "n".repeat(5000));
        let r = http(p, "POST", "/submit", None, &big).await;
        assert_eq!(r.status, 413, "{}", r.body);
        assert!(stub.dialed().is_empty());
        let ban = form(&[("ban", "198.51.100.9"), ("form", TOKEN), ("pad", &"p".repeat(5000))]);
        let r = http(a, "POST", "/ban", Some(&format!("x:{TOKEN}")), &ban).await;
        assert_eq!(r.status, 413, "{}", r.body);
        assert!(s.bans().is_empty());
        // under the limit, the same form is taken
        let ban = form(&[("ban", "198.51.100.9"), ("form", TOKEN), ("pad", &"p".repeat(3000))]);
        assert_eq!(http(a, "POST", "/ban", Some(&format!("x:{TOKEN}")), &ban).await.status, 303);
        assert_eq!(s.bans().len(), 1);
        s.close().await;
    });
}
