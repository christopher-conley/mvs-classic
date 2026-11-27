//! The registry's rules over its members: who connects and checks in, the address checks that list a relay, what
//! each member hears of the others, and the admin's allow list and bans.

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;

use mvs_protocol::registry_wire::{Counts, FromRegistry, RelayEntry};
use mvs_protocol::relay_wire::{RELAY_WIRE_VERSION, key_id};
use mvs_registry::core::{
    Admission, Approved, BAD_CHECK_IN, BUSY, DENIED, Due, Limits, Member, MemberKey, Mode, NOT_IN_TIME, NOT_LISTED,
    OTHER_ADDRESS, OTHER_WIRE, Origin, Proof, REPLACED, Registry, SILENT, SLOW_DOWN,
};
use mvs_registry::rules::{Ban, Bans, NEVER, NO_IPV6, NOT_PUBLIC};

const WIRE: u32 = RELAY_WIRE_VERSION;
const PROTO: u32 = 33;

#[derive(Default)]
struct FakeState {
    sent: Vec<FromRegistry>,
    refused: Vec<String>,
    /// Sends are answered false (the connection can take no more).
    lost: bool,
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<FakeState>>);

impl Member for Fake {
    fn send(&mut self, m: &FromRegistry) -> bool {
        let mut s = self.0.borrow_mut();
        if s.lost {
            return false;
        }
        s.sent.push(m.clone());
        true
    }
    fn refuse(&mut self, why: &str) {
        self.0.borrow_mut().refused.push(why.to_string());
    }
}

impl Fake {
    fn take(&self) -> Vec<FromRegistry> {
        std::mem::take(&mut self.0.borrow_mut().sent)
    }
    fn refused(&self) -> Vec<String> {
        self.0.borrow().refused.clone()
    }
}

type Log = Rc<RefCell<Vec<String>>>;

fn registry(mode: Mode, approved: Vec<Approved>, bans: Vec<Ban>, limits: Limits) -> (Registry, Log) {
    let log = Log::default();
    let to = log.clone();
    let admission = Admission { mode, approved, bans: Bans::new(bans) };
    (Registry::new(WIRE, admission, limits, Box::new(move |line: &str| to.borrow_mut().push(line.to_string()))), log)
}

fn open() -> Registry {
    registry(Mode::Open, vec![], vec![], Limits::default()).0
}

fn with(limits: Limits) -> Registry {
    registry(Mode::Open, vec![], vec![], limits).0
}

fn id(n: u8) -> String {
    key_id(&[n; 32])
}

fn source(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, n)
}

fn v4(text: &str) -> Ipv4Addr {
    text.parse().unwrap_or_else(|_| panic!("{text} is an IPv4 address"))
}

fn public(n: u8) -> String {
    format!("198.51.100.{n}:7777")
}

fn counts() -> Counts {
    Counts { players: 1, max_players: 500, matches: 0, max_matches: 250 }
}

fn approved(n: u8, address: Option<&str>, origin: Origin) -> Approved {
    Approved { id: id(n), address: address.map(str::to_string), name: None, origin }
}

fn entry(n: u8, address: &str, approved: bool) -> RelayEntry {
    RelayEntry { id: id(n), address: address.to_string(), name: None, approved }
}

fn up(n: u8) -> FromRegistry {
    FromRegistry::RelayUp { relay: entry(n, &public(n), false) }
}

fn gone(n: u8) -> FromRegistry {
    FromRegistry::RelayGone { id: id(n) }
}

fn connect(r: &mut Registry, from: Ipv4Addr, now: f64) -> (MemberKey, Fake) {
    let f = Fake::default();
    let k = r.connect(from, Box::new(f.clone()), now).expect("connected");
    (k, f)
}

/// A member from `source(n)` through its hello (as `id(n)`) and its proof.
fn proved(r: &mut Registry, n: u8, now: f64) -> (MemberKey, Fake) {
    let (k, f) = connect(r, source(n), now);
    r.hello(k, &id(n), now).expect("hello taken");
    r.proved(k, now);
    (k, f)
}

/// Connected member `k` through hello, proof, a check-in at `address` and its lookup to `ip`: the address to check.
fn check(
    r: &mut Registry,
    k: MemberKey,
    n: u8,
    proto: u32,
    address: &str,
    ip: Ipv4Addr,
    now: f64,
) -> Result<SocketAddrV4, &'static str> {
    r.hello(k, &id(n), now)?;
    r.proved(k, now);
    r.check_in(k, address, WIRE, proto, counts(), now)?;
    r.resolved(k, ip, now)
}

/// Connected member `k` the whole way to its listing.
fn list(r: &mut Registry, k: MemberKey, n: u8, proto: u32, address: &str, ip: Ipv4Addr, now: f64) {
    let at = check(r, k, n, proto, address, ip, now).expect("an address to check");
    r.verified(k, Proof::Proved, now);
    assert!(r.relays(proto).iter().any(|e| e.id == id(n) && e.address == at.to_string()), "{n} listed");
}

fn listed_at(r: &mut Registry, n: u8, proto: u32, address: &str, ip: Ipv4Addr, now: f64) -> (MemberKey, Fake) {
    let (k, f) = connect(r, source(n), now);
    list(r, k, n, proto, address, ip, now);
    (k, f)
}

/// `id(n)` listed at `198.51.100.n:7777`, its check-in that address.
fn listed(r: &mut Registry, n: u8, proto: u32, now: f64) -> (MemberKey, Fake) {
    listed_at(r, n, proto, &public(n), Ipv4Addr::new(198, 51, 100, n), now)
}

#[test]
fn an_open_registry_lists_any_relay() {
    let (mut r, log) = registry(Mode::Open, vec![], vec![], Limits::default());
    let (k, f) = listed(&mut r, 1, PROTO, 0.0);
    assert_eq!(r.relays(PROTO), vec![entry(1, &public(1), false)]);
    assert!(f.take().is_empty(), "alone, it hears of nobody");
    assert_eq!(*log.borrow(), vec![format!("listed {} at {}", id(1), public(1))]);
    let seen = r.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].key, k);
    assert_eq!(seen[0].source, source(1));
    assert_eq!(seen[0].id, Some(id(1)));
    assert_eq!(seen[0].address, Some(public(1)));
    assert!(seen[0].listed && !seen[0].approved);
    assert_eq!(seen[0].counts, Some(counts()));
}

#[test]
fn a_relay_off_the_list_is_refused_in_list_mode() {
    let two = Approved { name: Some("Two".into()), ..approved(2, None, Origin::Config) };
    let (mut r, _) = registry(Mode::List, vec![two], vec![], Limits::default());
    let (k, f) = connect(&mut r, source(1), 0.0);
    assert_eq!(r.hello(k, &id(1), 0.0), Err(NOT_LISTED));
    assert_eq!(f.refused(), [NOT_LISTED]);
    assert!(r.seen().is_empty());
    listed(&mut r, 2, PROTO, 0.0);
    let want = RelayEntry { id: id(2), address: public(2), name: Some("Two".into()), approved: true };
    assert_eq!(r.relays(PROTO), vec![want]);
}

#[test]
fn a_banned_id_is_refused_in_either_mode() {
    for mode in [Mode::Open, Mode::List] {
        let (mut r, _) =
            registry(mode, vec![approved(1, None, Origin::Config)], vec![Ban::Id(id(1))], Limits::default());
        let (k, f) = connect(&mut r, source(1), 0.0);
        assert_eq!(r.hello(k, &id(1), 0.0), Err(DENIED), "{mode:?}");
        assert_eq!(f.refused(), [DENIED], "{mode:?}");
        assert!(r.seen().is_empty(), "{mode:?}");
    }
}

#[test]
fn a_banned_source_is_refused_at_connect() {
    for ban in [Ban::Ip(source(1)), Ban::Range(source(0), source(9)), Ban::Cidr(Ipv4Addr::new(203, 0, 113, 0), 24)] {
        let (mut r, _) = registry(Mode::Open, vec![], vec![ban.clone()], Limits::default());
        let f = Fake::default();
        assert_eq!(r.connect(source(1), Box::new(f.clone()), 0.0), Err(DENIED), "{ban:?}");
        assert!(f.refused().is_empty(), "the server closes it with the reason");
        assert!(r.connect(v4("192.0.2.1"), Box::new(Fake::default()), 0.0).is_ok(), "{ban:?} holds another");
    }
}

#[test]
fn one_source_has_its_bound() {
    let mut r = with(Limits { per_address: 2, ..Limits::default() });
    // One listed and one not: both count.
    let (a, _) = connect(&mut r, source(1), 0.0);
    list(&mut r, a, 1, PROTO, &public(1), v4("198.51.100.1"), 0.0);
    let (b, _) = connect(&mut r, source(1), 0.0);
    assert_eq!(r.connect(source(1), Box::new(Fake::default()), 0.0), Err(BUSY));
    assert!(r.connect(source(2), Box::new(Fake::default()), 0.0).is_ok(), "another source has its own");
    r.leave(b, 0.0);
    assert!(r.connect(source(1), Box::new(Fake::default()), 0.0).is_ok(), "one more once one left");
    assert_eq!(r.connect(source(1), Box::new(Fake::default()), 0.0), Err(BUSY));
}

#[test]
fn connections_have_a_rate() {
    let mut r = with(Limits { per_address: 2, connects_per_minute: 3.0, ..Limits::default() });
    let (a, _) = connect(&mut r, source(1), 0.0);
    let (b, _) = connect(&mut r, source(1), 0.0);
    assert_eq!(r.connect(source(1), Box::new(Fake::default()), 0.0), Err(BUSY));
    r.leave(a, 0.0);
    // The refused one took no token: the third is taken.
    let (c, _) = connect(&mut r, source(1), 0.0);
    r.leave(b, 0.0);
    r.leave(c, 0.0);
    assert_eq!(r.connect(source(1), Box::new(Fake::default()), 0.0), Err(SLOW_DOWN), "the fourth in the minute");
    assert!(r.connect(source(2), Box::new(Fake::default()), 0.0).is_ok(), "another source has its own");
    assert!(r.connect(source(1), Box::new(Fake::default()), 60000.0).is_ok(), "one more a minute later");
}

#[test]
fn listed_only_once_verified() {
    let mut r = open();
    let (_, fb) = listed(&mut r, 2, PROTO, 0.0);
    let (a, _) = connect(&mut r, source(1), 0.0);
    let at = check(&mut r, a, 1, PROTO, &public(1), v4("198.51.100.1"), 0.0).unwrap();
    assert_eq!(at.to_string(), public(1));
    assert_eq!(r.relays(PROTO).len(), 1, "not listed while its check is out");
    assert!(fb.take().is_empty());
    let seen = r.seen();
    assert!(!seen[1].listed);
    r.verified(a, Proof::Proved, 0.0);
    assert_eq!(r.relays(PROTO).len(), 2);
    assert_eq!(fb.take(), [up(1)]);
}

#[test]
fn another_key_is_refused_at_once() {
    let mut r = open();
    let (a, f) = connect(&mut r, source(1), 0.0);
    check(&mut r, a, 1, PROTO, &public(1), v4("198.51.100.1"), 0.0).unwrap();
    r.verified(a, Proof::OtherKey, 0.0);
    assert_eq!(f.refused(), [OTHER_ADDRESS]);
    assert!(r.seen().is_empty());
    assert!(r.due(1e9).is_empty(), "no check due");
}

#[test]
fn a_check_with_no_answer_is_tried_again() {
    let mut r = with(Limits { recheck_ms: 100.0, ..Limits::default() });
    let (a, f) = connect(&mut r, source(1), 0.0);
    check(&mut r, a, 1, PROTO, &public(1), v4("198.51.100.1"), 0.0).unwrap();
    r.verified(a, Proof::NoAnswer, 0.0);
    let again = || vec![Due::Check { key: a, host: "198.51.100.1".into(), port: 7777 }];
    for (before, at, proof) in
        [(99.0, 100.0, Proof::NoAnswer), (299.0, 300.0, Proof::NoAnswer), (699.0, 700.0, Proof::Proved)]
    {
        assert!(r.due(before).is_empty(), "nothing due at {before}");
        assert_eq!(r.due(at), again(), "a check due at {at}");
        assert!(r.due(at).is_empty(), "handed out once");
        assert_eq!(r.resolved(a, v4("198.51.100.1"), at).unwrap().to_string(), public(1));
        r.verified(a, proof, at);
    }
    assert_eq!(r.relays(PROTO), vec![entry(1, &public(1), false)]);
    assert!(f.refused().is_empty());
}

#[test]
fn a_failed_lookup_is_tried_again() {
    let mut r = with(Limits { recheck_ms: 100.0, ..Limits::default() });
    let (a, _) = proved(&mut r, 1, 0.0);
    let to = r.check_in(a, "Relay.Example.:7777", WIRE, PROTO, counts(), 0.0);
    assert_eq!(to, Ok(("relay.example".to_string(), 7777)));
    r.unresolved(a, 0.0);
    assert!(r.due(99.0).is_empty());
    assert_eq!(r.due(100.0), [Due::Check { key: a, host: "relay.example".into(), port: 7777 }]);
    let at = r.resolved(a, v4("198.51.100.7"), 100.0).unwrap();
    r.verified(a, Proof::Proved, 100.0);
    assert_eq!(r.relays(PROTO), vec![entry(1, &at.to_string(), false)]);
}

#[test]
fn relays_of_one_group_hear_of_each_other() {
    let (mut r, log) = registry(Mode::Open, vec![], vec![], Limits::default());
    let (a, fa) = listed(&mut r, 1, 33, 0.0);
    let (_, fb) = listed(&mut r, 2, 33, 0.0);
    assert_eq!(fa.take(), [up(2)]);
    assert_eq!(fb.take(), [up(1)]);
    let (_, fc) = listed(&mut r, 3, 32, 0.0);
    assert!(fa.take().is_empty() && fb.take().is_empty(), "another protocol is another group");
    assert!(fc.take().is_empty());
    assert_eq!(r.relays(32), vec![entry(3, &public(3), false)]);
    r.leave(a, 1.0);
    assert_eq!(fb.take(), [gone(1)]);
    assert!(fc.take().is_empty());
    assert!(fa.refused().is_empty());
    assert_eq!(log.borrow().last(), Some(&format!("gone {}", id(1))));
}

#[test]
fn the_listed_address_is_the_verified_ip() {
    let (mut r, log) = registry(Mode::Open, vec![], vec![], Limits::default());
    listed_at(&mut r, 1, PROTO, "relay.example:7777", v4("198.51.100.7"), 0.0);
    assert_eq!(r.relays(PROTO), vec![entry(1, "198.51.100.7:7777", false)]);
    assert_eq!(*log.borrow(), vec![format!("listed {} at 198.51.100.7:7777", id(1))]);
}

#[test]
fn a_private_address_needs_the_config() {
    let entries = vec![
        approved(2, Some("10.0.0.5:7777"), Origin::Config),
        approved(3, Some("10.0.0.5:7777"), Origin::Config),
        approved(5, Some("10.0.0.5:7777"), Origin::Page),
        approved(6, Some("10.0.0.5:7778"), Origin::Config),
        approved(7, Some("Relay.LAN:7777"), Origin::Config),
        approved(8, Some("10.0.0.8:7777"), Origin::Config),
    ];
    let (mut r, _) = registry(Mode::Open, entries, vec![], Limits::default());
    let ten = v4("10.0.0.5");
    let refused = |r: &mut Registry, n: u8, address: &str, ip: Ipv4Addr| {
        let (k, f) = connect(r, source(n), 0.0);
        assert_eq!(check(r, k, n, PROTO, address, ip, 0.0), Err(NOT_PUBLIC), "{n}");
        assert_eq!(f.refused(), [NOT_PUBLIC], "{n}");
    };
    refused(&mut r, 1, "10.0.0.5:7777", ten);
    // Another id's entry, and an entry of the right host at another port.
    refused(&mut r, 4, "10.0.0.5:7777", ten);
    refused(&mut r, 6, "10.0.0.5:7777", ten);
    // An entry's address is not the private address its id's name resolved to.
    refused(&mut r, 8, "relay.lan:7777", v4("10.0.0.9"));
    listed_at(&mut r, 2, PROTO, "10.0.0.5:7777", ten, 0.0);
    listed_at(&mut r, 5, PROTO, "10.0.0.5:7777", ten, 0.0);
    // The check-in's name as the entry gives it, case and a trailing dot aside.
    listed_at(&mut r, 7, PROTO, "relay.lan.:7777", v4("10.0.0.6"), 0.0);
    // The entry's address as the name resolved.
    let (k, _) = connect(&mut r, source(9), 0.0);
    r.hello(k, &id(8), 0.0).unwrap();
    r.proved(k, 0.0);
    r.check_in(k, "relay.lan:7777", WIRE, PROTO, counts(), 0.0).unwrap();
    assert_eq!(r.resolved(k, v4("10.0.0.8"), 0.0).unwrap().to_string(), "10.0.0.8:7777");
}

#[test]
fn never_is_never() {
    let entry = approved(1, Some("169.254.169.254:7777"), Origin::Config);
    let (mut r, _) = registry(Mode::Open, vec![entry], vec![], Limits::default());
    let (k, f) = connect(&mut r, source(1), 0.0);
    assert_eq!(check(&mut r, k, 1, PROTO, "169.254.169.254:7777", v4("169.254.169.254"), 0.0), Err(NEVER));
    assert_eq!(f.refused(), [NEVER]);
}

#[test]
fn an_ipv6_check_in_is_refused() {
    let mut r = open();
    for (n, address) in [(1, "[2001:db8::1]:7777"), (2, "2001:db8::1")] {
        let (k, f) = proved(&mut r, n, 0.0);
        assert_eq!(r.check_in(k, address, WIRE, PROTO, counts(), 0.0), Err(NO_IPV6), "{address}");
        assert_eq!(f.refused(), [NO_IPV6]);
    }
    assert!(r.seen().is_empty());
}

#[test]
fn a_banned_host_or_ip_is_refused_at_check_in() {
    let bans = vec![Ban::Host("relay.example".into()), Ban::Ip(v4("198.51.100.9"))];
    let (mut r, log) = registry(Mode::Open, vec![], bans, Limits::default());
    let (a, fa) = proved(&mut r, 1, 0.0);
    assert_eq!(r.check_in(a, "RELAY.example:7777", WIRE, PROTO, counts(), 0.0), Err(DENIED));
    assert_eq!(fa.refused(), [DENIED]);
    let (b, fb) = connect(&mut r, source(2), 0.0);
    assert_eq!(check(&mut r, b, 2, PROTO, "other.example:7777", v4("198.51.100.9"), 0.0), Err(DENIED));
    assert_eq!(fb.refused(), [DENIED]);
    assert_eq!(*log.borrow(), vec![format!("refused {}: {DENIED}", id(1)), format!("refused {}: {DENIED}", id(2))]);
}

#[test]
fn another_wire_is_refused() {
    let mut r = open();
    let (k, f) = proved(&mut r, 1, 0.0);
    assert_eq!(r.check_in(k, &public(1), WIRE + 1, PROTO, counts(), 0.0), Err(OTHER_WIRE));
    assert_eq!(f.refused(), [OTHER_WIRE]);
    assert!(r.seen().is_empty());
}

#[test]
fn a_bad_check_in_is_refused() {
    let mut r = open();
    for (n, address) in [(1, "not an address"), (2, "198.51.100.2:0"), (3, "198.51.100.3:x")] {
        let (k, f) = proved(&mut r, n, 0.0);
        assert_eq!(r.check_in(k, address, WIRE, PROTO, counts(), 0.0), Err(BAD_CHECK_IN), "{address}");
        assert_eq!(f.refused(), [BAD_CHECK_IN], "{address}");
    }
    // A second check-in.
    let (k, f) = proved(&mut r, 4, 0.0);
    assert!(r.check_in(k, &public(4), WIRE, PROTO, counts(), 0.0).is_ok());
    assert_eq!(r.check_in(k, &public(4), WIRE, PROTO, counts(), 0.0), Err(BAD_CHECK_IN));
    assert_eq!(f.refused(), [BAD_CHECK_IN]);
    // A check-in before the key is proved.
    let (k, f) = connect(&mut r, source(5), 0.0);
    r.hello(k, &id(5), 0.0).unwrap();
    assert_eq!(r.check_in(k, &public(5), WIRE, PROTO, counts(), 0.0), Err(BAD_CHECK_IN));
    assert_eq!(f.refused(), [BAD_CHECK_IN]);
    // A proof before the hello.
    let (k, f) = connect(&mut r, source(6), 0.0);
    r.proved(k, 0.0);
    assert_eq!(f.refused(), [BAD_CHECK_IN]);
    assert!(r.seen().is_empty());
}

#[test]
fn a_beat_is_answered_and_tells_nobody() {
    let mut r = open();
    let (_, fa) = listed(&mut r, 1, PROTO, 0.0);
    let (b, fb) = listed(&mut r, 2, PROTO, 0.0);
    fa.take();
    fb.take();
    let more = Counts { players: 9000, ..counts() };
    r.beat(b, more, 10.0);
    assert_eq!(fb.take(), [FromRegistry::Beat {}]);
    assert!(fa.take().is_empty());
    assert_eq!(r.seen()[1].counts, Some(more), "kept as sent, above its own limit too");
    // A connection that can take no more is let go as a leave.
    fb.0.borrow_mut().lost = true;
    r.beat(b, counts(), 20.0);
    assert!(fb.refused().is_empty());
    assert_eq!(fa.take(), [gone(2)]);
    assert_eq!(r.relays(PROTO), vec![entry(1, &public(1), false)]);
}

#[test]
fn a_beat_before_check_in_is_refused() {
    let mut r = open();
    let (k, f) = proved(&mut r, 1, 0.0);
    r.beat(k, counts(), 0.0);
    assert_eq!(f.refused(), [BAD_CHECK_IN]);
    assert!(f.take().is_empty());
    assert!(r.seen().is_empty());
}

#[test]
fn a_silent_member_goes() {
    let mut r = with(Limits { silent_ms: 100.0, ..Limits::default() });
    let (_, fa) = listed(&mut r, 1, PROTO, 0.0);
    let (b, fb) = listed(&mut r, 2, PROTO, 0.0);
    fa.take();
    fb.take();
    r.beat(b, counts(), 100.0);
    r.expire(101.0);
    assert_eq!(fa.refused(), [SILENT]);
    assert_eq!(fb.take(), [FromRegistry::Beat {}, gone(1)]);
    assert!(fb.refused().is_empty());
    assert_eq!(r.relays(PROTO), vec![entry(2, &public(2), false)]);
}

#[test]
fn a_member_not_listed_in_time_goes() {
    // Out of checks.
    let mut r = with(Limits { checks: 3, recheck_ms: 100.0, ..Limits::default() });
    let (a, f) = connect(&mut r, source(1), 0.0);
    check(&mut r, a, 1, PROTO, &public(1), v4("198.51.100.1"), 0.0).unwrap();
    r.verified(a, Proof::NoAnswer, 0.0);
    for at in [100.0, 300.0] {
        assert_eq!(r.due(at).len(), 1);
        r.resolved(a, v4("198.51.100.1"), at).unwrap();
        r.verified(a, Proof::NoAnswer, at);
    }
    assert_eq!(f.refused(), [NOT_IN_TIME]);
    assert!(r.seen().is_empty());
    r.expire(1e9);
    assert!(r.due(1e9).is_empty());
    assert_eq!(f.refused(), [NOT_IN_TIME], "once");

    // Out of time.
    let mut r = with(Limits { list_ms: 250.0, recheck_ms: 100.0, ..Limits::default() });
    let (a, f) = connect(&mut r, source(1), 0.0);
    check(&mut r, a, 1, PROTO, &public(1), v4("198.51.100.1"), 0.0).unwrap();
    r.verified(a, Proof::NoAnswer, 0.0);
    assert_eq!(r.due(100.0).len(), 1);
    r.resolved(a, v4("198.51.100.1"), 100.0).unwrap();
    r.verified(a, Proof::NoAnswer, 100.0);
    r.expire(249.0);
    assert!(f.refused().is_empty());
    r.expire(250.0);
    assert_eq!(f.refused(), [NOT_IN_TIME]);
    r.expire(400.0);
    assert!(r.due(400.0).is_empty());
    assert_eq!(f.refused(), [NOT_IN_TIME], "once");
}

/// A registry with `refresh_ms: 100`, member 1 listed by its check-in `relay.example:7777` at 198.51.100.7, and
/// member 2 in its group, both with nothing more to hear.
fn named() -> (Registry, MemberKey, Fake, Fake) {
    let mut r = with(Limits { refresh_ms: 100.0, ..Limits::default() });
    let (a, fa) = listed_at(&mut r, 1, PROTO, "relay.example:7777", v4("198.51.100.7"), 0.0);
    let (_, fb) = listed(&mut r, 2, PROTO, 0.0);
    fa.take();
    fb.take();
    (r, a, fa, fb)
}

#[test]
fn a_name_is_refreshed() {
    let (mut r, a, fa, fb) = named();
    assert!(r.due(99.0).is_empty());
    assert_eq!(r.due(100.0), [Due::Refresh { key: a, host: "relay.example".into(), port: 7777 }]);
    assert!(r.due(100.0).is_empty(), "handed out once");
    let to = r.refreshed(a, v4("198.51.100.8"), 100.0).expect("a new address to prove");
    assert_eq!(to.to_string(), "198.51.100.8:7777");
    r.moved(a, to, Proof::Proved, 100.0);
    assert_eq!(fb.take(), [FromRegistry::RelayUp { relay: entry(1, "198.51.100.8:7777", false) }]);
    assert!(fa.take().is_empty());
    assert_eq!(r.relays(PROTO)[0], entry(1, "198.51.100.8:7777", false));
    assert!(r.due(199.0).is_empty());
    assert_eq!(r.due(200.0).len(), 1, "refreshed again");
}

#[test]
fn a_refresh_to_the_same_ip_does_nothing() {
    let (mut r, a, fa, fb) = named();
    assert_eq!(r.due(100.0).len(), 1);
    assert_eq!(r.refreshed(a, v4("198.51.100.7"), 100.0), None);
    assert!(fa.take().is_empty() && fb.take().is_empty());
    assert!(fa.refused().is_empty());
    assert_eq!(r.relays(PROTO)[0], entry(1, "198.51.100.7:7777", false));
    assert!(r.due(199.0).is_empty());
    assert_eq!(r.due(200.0).len(), 1);
}

#[test]
fn a_refresh_to_a_private_ip_lets_it_go() {
    let (mut r, a, fa, fb) = named();
    assert_eq!(r.due(100.0).len(), 1);
    assert_eq!(r.refreshed(a, v4("10.0.0.5"), 100.0), None);
    assert_eq!(fa.refused(), [NOT_PUBLIC]);
    assert_eq!(fb.take(), [gone(1)]);
    assert_eq!(r.relays(PROTO), vec![entry(2, &public(2), false)]);
}

#[test]
fn a_refresh_whose_check_fails_keeps_the_old_address() {
    let (mut r, a, fa, fb) = named();
    assert_eq!(r.due(100.0).len(), 1);
    let to = r.refreshed(a, v4("198.51.100.8"), 100.0).unwrap();
    r.moved(a, to, Proof::NoAnswer, 100.0);
    assert_eq!(r.relays(PROTO)[0], entry(1, "198.51.100.7:7777", false));
    assert!(fb.take().is_empty());
    // And one whose lookup fails.
    assert!(r.due(199.0).is_empty());
    assert_eq!(r.due(200.0).len(), 1);
    r.unresolved(a, 200.0);
    assert_eq!(r.relays(PROTO)[0], entry(1, "198.51.100.7:7777", false));
    assert!(fb.take().is_empty());
    assert!(fa.refused().is_empty());
    assert_eq!(r.due(300.0).len(), 1, "refreshed again");
}

#[test]
fn an_ip_check_in_is_never_refreshed() {
    let mut r = with(Limits { refresh_ms: 100.0, ..Limits::default() });
    listed(&mut r, 1, PROTO, 0.0);
    assert!(r.due(1e9).is_empty());
}

#[test]
fn a_second_connection_of_an_id_replaces_the_first() {
    let mut r = open();
    let (_, first) = listed(&mut r, 1, PROTO, 0.0);
    let (_, fb) = listed(&mut r, 2, PROTO, 0.0);
    first.take();
    fb.take();
    let (k, second) = connect(&mut r, source(11), 1.0);
    r.hello(k, &id(1), 1.0).unwrap();
    assert!(first.refused().is_empty(), "not before its key is proved");
    r.proved(k, 1.0);
    assert_eq!(first.refused(), [REPLACED]);
    assert_eq!(fb.take(), [gone(1)]);
    assert_eq!(r.relays(PROTO), vec![entry(2, &public(2), false)]);
    r.check_in(k, &public(1), WIRE, PROTO, counts(), 1.0).unwrap();
    r.resolved(k, v4("198.51.100.1"), 1.0).unwrap();
    r.verified(k, Proof::Proved, 1.0);
    assert_eq!(fb.take(), [up(1)]);
    assert_eq!(second.take(), [up(2)]);
    assert_eq!(r.relays(PROTO).iter().filter(|e| e.id == id(1)).count(), 1);
    assert!(second.refused().is_empty());
}

#[test]
fn approving_a_listed_relay_tells_its_group() {
    let mut r = open();
    let (_, fa) = listed(&mut r, 1, PROTO, 0.0);
    let (_, fb) = listed(&mut r, 2, PROTO, 0.0);
    fa.take();
    fb.take();
    let one = Approved { name: Some("One".into()), ..approved(1, None, Origin::Page) };
    r.approve(one, 1.0);
    let want = RelayEntry { id: id(1), address: public(1), name: Some("One".into()), approved: true };
    assert_eq!(fb.take(), [FromRegistry::RelayUp { relay: want.clone() }]);
    assert!(fa.take().is_empty());
    assert_eq!(r.relays(PROTO)[0], want);
    // An entry of the same id replaces it.
    r.approve(Approved { name: Some("Uno".into()), ..approved(1, None, Origin::Config) }, 2.0);
    assert_eq!(r.approved().len(), 1);
    assert_eq!(r.approved()[0].name.as_deref(), Some("Uno"));
    assert_eq!(fb.take().len(), 1);
}

#[test]
fn unapproving_in_list_mode_lets_it_go() {
    let entries = vec![approved(1, None, Origin::Config), approved(2, None, Origin::Page)];
    let (mut r, _) = registry(Mode::List, entries, vec![], Limits::default());
    let (_, fa) = listed(&mut r, 1, PROTO, 0.0);
    let (_, fb) = listed(&mut r, 2, PROTO, 0.0);
    fa.take();
    fb.take();
    assert!(r.unapprove(&id(1), 1.0));
    assert_eq!(fa.refused(), [NOT_LISTED]);
    assert_eq!(fb.take(), [gone(1)]);
    assert!(!r.unapprove(&id(1), 1.0), "no such id");
    assert_eq!(r.approved().len(), 1);

    // In open mode it stays, its group told it is no longer approved.
    let (mut r, _) = registry(Mode::Open, vec![approved(3, None, Origin::Config)], vec![], Limits::default());
    let (_, fc) = listed(&mut r, 3, PROTO, 0.0);
    let (_, fd) = listed(&mut r, 4, PROTO, 0.0);
    fc.take();
    fd.take();
    assert!(r.unapprove(&id(3), 1.0));
    assert!(fc.refused().is_empty());
    assert_eq!(fd.take(), [up(3)]);
}

#[test]
fn banning_a_listed_relay_lets_it_go() {
    let mut r = open();
    let (_, fa) = listed(&mut r, 1, PROTO, 0.0);
    let (_, fb) = listed(&mut r, 2, PROTO, 0.0);
    let (_, fc) = listed_at(&mut r, 3, PROTO, "192.0.2.3:7777", v4("192.0.2.3"), 0.0);
    let (_, fd) = listed_at(&mut r, 4, PROTO, "relay.example:7777", v4("198.51.100.4"), 0.0);
    fb.take();
    assert!(r.ban(Ban::Id(id(1)), 1.0));
    assert!(!r.ban(Ban::Id(id(1)), 1.0), "already there");
    assert_eq!(fa.refused(), [DENIED]);
    assert_eq!(fb.take(), [gone(1)]);
    assert!(r.ban(Ban::Cidr(v4("192.0.2.0"), 24), 1.0));
    assert_eq!(fc.refused(), [DENIED]);
    assert_eq!(fb.take(), [gone(3)]);
    assert!(r.ban(Ban::Host("relay.example".into()), 1.0));
    assert_eq!(fd.refused(), [DENIED]);
    assert_eq!(fb.take(), [gone(4)]);
    assert!(fb.refused().is_empty());
    assert_eq!(r.relays(PROTO), vec![entry(2, &public(2), false)]);
    assert_eq!(r.bans().len(), 3);
}

#[test]
fn a_ban_added_during_a_check_holds() {
    // A ban of the address being checked.
    let mut r = open();
    let (a, fa) = connect(&mut r, source(1), 0.0);
    let at = check(&mut r, a, 1, PROTO, &public(1), v4("198.51.100.1"), 0.0).unwrap();
    assert!(r.ban(Ban::Ip(*at.ip()), 1.0));
    assert!(fa.refused().is_empty(), "neither its source nor a listed address");
    r.verified(a, Proof::Proved, 1.0);
    assert_eq!(fa.refused(), [DENIED]);
    assert!(fa.take().is_empty());
    assert!(r.relays(PROTO).is_empty() && r.seen().is_empty());

    // A ban over a refresh's new address.
    let (mut r, a, fa, fb) = named();
    assert_eq!(r.due(100.0).len(), 1);
    let to = r.refreshed(a, v4("198.51.100.200"), 100.0).unwrap();
    assert!(r.ban(Ban::Cidr(v4("198.51.100.128"), 25), 100.0));
    assert!(fa.refused().is_empty());
    r.moved(a, to, Proof::Proved, 100.0);
    assert_eq!(fa.refused(), [DENIED]);
    assert_eq!(fb.take(), [gone(1)]);
    assert_eq!(r.relays(PROTO), vec![entry(2, &public(2), false)]);
}
