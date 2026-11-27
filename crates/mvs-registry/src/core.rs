//! The registry's rules over its members: who may connect and check in, the address checks that list a relay, the
//! relay list each member hears as changes, and the admin's allow list and bans. Synchronous and sans-IO: the server
//! owns it, calls it with the clock, and makes the lookups and the dials it asks for. The port's own.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};

use indexmap::IndexMap;
use mvs_protocol::registry_wire::{Counts, FromRegistry, RelayEntry, SILENT_MS};
use mvs_protocol::relay_wire::parse_address;
use mvs_relay::limits::Buckets;

use crate::rules::{Ban, Bans, NO_IPV6, Source, may_dial};

/// Who may be listed: in `Open` any relay not banned (the approved ones marked so), in `List` only an approved one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Open,
    List,
}

/// Where an allow list entry came from: the registry's config, or the admin's web page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Config,
    Page,
}

/// A relay on the allow list. `address` (as `host:port`) is the one address of it the registry dials even when
/// private; a config entry may give one, a page entry has the one it was proved at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approved {
    pub id: String,
    pub address: Option<String>,
    pub name: Option<String>,
    pub origin: Origin,
}

/// Who may be listed, as the registry starts.
pub struct Admission {
    pub mode: Mode,
    pub approved: Vec<Approved>,
    pub bans: Bans,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Limits {
    /// Connections from one source address at once: 4.
    pub per_address: u32,
    /// New connections from one source address a minute (`Buckets::per_minute`): 12.
    pub connects_per_minute: f64,
    /// A member that sent nothing for this long is let go (ms): SILENT_MS.
    pub silent_ms: f64,
    /// A member not listed after `checks` address checks, or `list_ms` after its connection, is let go
    /// NOT_IN_TIME (ms): 6 and 600000. The first check again comes `recheck_ms` after a failed one, the wait
    /// doubling: 15000.
    pub checks: u32,
    pub list_ms: f64,
    pub recheck_ms: f64,
    /// A listed member whose check-in named a host name has it resolved again this often (ms): 60000.
    pub refresh_ms: f64,
    /// Dials of one target `ip:port` a minute, whatever asked for them (`Buckets::per_minute`): 12.
    pub dials_per_minute: f64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            per_address: 4,
            connects_per_minute: 12.0,
            silent_ms: SILENT_MS,
            checks: 6,
            list_ms: 600_000.0,
            recheck_ms: 15_000.0,
            refresh_ms: 60_000.0,
            dials_per_minute: 12.0,
        }
    }
}

/// An address check's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proof {
    Proved,
    OtherKey,
    NoAnswer,
}

/// What the server is to do for a member now (from `due`): look `host` up (an IPv4 literal is its own answer) and
/// answer through `resolved` or `unresolved` (a check), or through `refreshed` or `unresolved` (a refresh).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Due {
    Check { key: MemberKey, host: String, port: u16 },
    Refresh { key: MemberKey, host: String, port: u16 },
}

/// How the registry reaches one member. Its calls never call the registry back.
pub trait Member {
    /// False: the connection can take no more (it reads too slowly), and the registry lets the member go at once,
    /// as a leave.
    fn send(&mut self, m: &FromRegistry) -> bool;
    /// The member broke a rule: the server tells it refused { why } and closes (the registry has let it go already).
    fn refuse(&mut self, why: &str);
}

/// One connection, as the calls name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemberKey(u64);

/// What the admin page shows of one connection. `address` is the IPv4 address it is listed or being checked at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub key: MemberKey,
    pub source: Ipv4Addr,
    pub id: Option<String>,
    pub address: Option<String>,
    pub listed: bool,
    pub approved: bool,
    pub counts: Option<Counts>,
}

pub const DENIED: &str = "this relay is refused by the registry";
pub const NOT_LISTED: &str = "this relay is not on the registry's list";
pub const BUSY: &str = "too many relays from that address";
pub const SLOW_DOWN: &str = "too many connections from that address; try again later";
pub const REPLACED: &str = "checked in elsewhere";
pub const SILENT: &str = "silent";
pub const NOT_IN_TIME: &str = "not checked in in time";
pub const BAD_CHECK_IN: &str = "bad check-in";
pub const OTHER_WIRE: &str = "another relay wire version than this registry's";
pub const OTHER_ADDRESS: &str = "that address did not prove this relay's key";
/// The answer of a call on a member that is gone, or that waits for no such answer (nothing done).
pub const GONE: &str = "gone";

/// Where a member is on its way to its listing, and what is out for it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    /// No hello yet.
    Connected,
    /// Its hello named its id; its key not yet proved.
    Hello,
    /// Its key proved; no check-in yet.
    Proved,
    /// A lookup of its check-in's host is out.
    Lookup,
    /// An address check at this address is out.
    Dial(SocketAddrV4),
    /// Its last check failed: the next is due then.
    Wait(f64),
    Listed {
        at: SocketAddrV4,
        refresh: Refresh,
    },
}

/// A listed member's lookups of the host name its check-in named.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Refresh {
    /// Its check-in named an IPv4 address.
    Never,
    Due(f64),
    Lookup,
    /// The name resolved elsewhere: the check there is out.
    Dial(SocketAddrV4),
}

struct CheckIn {
    /// An IPv4 literal as its text, or a host name lowercase with a trailing dot dropped.
    host: String,
    named: bool,
    port: u16,
    proto: u32,
}

struct Conn {
    m: Box<dyn Member>,
    source: Ipv4Addr,
    since: f64,
    /// When it last sent something.
    heard: f64,
    id: Option<String>,
    check_in: Option<CheckIn>,
    counts: Option<Counts>,
    /// The address checks begun, its first lookup's included.
    checks: u32,
    state: State,
}

impl Conn {
    fn proved(&self) -> bool {
        !matches!(self.state, State::Connected | State::Hello)
    }

    fn listed_at(&self) -> Option<SocketAddrV4> {
        match self.state {
            State::Listed { at, .. } => Some(at),
            _ => None,
        }
    }

    /// Its group's protocol, when listed.
    fn group(&self) -> Option<u32> {
        self.listed_at().and(self.check_in.as_ref()).map(|c| c.proto)
    }

    /// Who it is in a log line: its id, or before its hello its source address.
    fn who(&self) -> String {
        self.id.clone().unwrap_or_else(|| self.source.to_string())
    }
}

/// A host name as bans and refreshes keep it: lowercase, a trailing dot dropped.
fn host_key(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

pub struct Registry {
    wire: u32,
    mode: Mode,
    approved: Vec<Approved>,
    bans: Bans,
    limits: Limits,
    log: Box<dyn FnMut(&str)>,
    rates: Buckets,
    /// Dials by target, keyed by its `ip:port`.
    dials: Buckets,
    /// In the order of their connections.
    members: IndexMap<MemberKey, Conn>,
    next: u64,
}

impl Registry {
    /// `wire` is the relay wire version a member must check in with. The log is given ids, IPs and reasons only,
    /// never a text a relay sent.
    pub fn new(wire: u32, admission: Admission, limits: Limits, log: Box<dyn FnMut(&str)>) -> Registry {
        Registry {
            wire,
            mode: admission.mode,
            approved: admission.approved,
            bans: admission.bans,
            rates: Buckets::per_minute(limits.connects_per_minute),
            dials: Buckets::per_minute(limits.dials_per_minute),
            limits,
            log,
            members: IndexMap::new(),
            next: 0,
        }
    }

    /// A connection from `source`: Err(DENIED) for a banned IP, Err(BUSY) at `per_address` (its members now, listed
    /// or not), Err(SLOW_DOWN) past the rate (counted only for connections taken). The server closes a refused one
    /// with the reason.
    pub fn connect(&mut self, source: Ipv4Addr, m: Box<dyn Member>, now: f64) -> Result<MemberKey, &'static str> {
        let here = self.members.values().filter(|c| c.source == source).count();
        let why = if self.bans.bans_ip(source) {
            Some(DENIED)
        } else if here >= self.limits.per_address as usize {
            Some(BUSY)
        } else if !self.rates.get(&source.to_string(), now).take(1.0, now) {
            Some(SLOW_DOWN)
        } else {
            None
        };
        if let Some(why) = why {
            (self.log)(&format!("refused {source}: {why}"));
            return Err(why);
        }
        self.next += 1;
        let k = MemberKey(self.next);
        let c = Conn {
            m,
            source,
            since: now,
            heard: now,
            id: None,
            check_in: None,
            counts: None,
            checks: 0,
            state: State::Connected,
        };
        self.members.insert(k, c);
        Ok(k)
    }

    /// Its hello names `id`, before any signature is made: Err(DENIED) for a banned id; Err(NOT_LISTED) in `List`
    /// mode for an id not approved; Err(BAD_CHECK_IN) for a second hello. The member is refused and let go on Err.
    pub fn hello(&mut self, k: MemberKey, id: &str, now: f64) -> Result<(), &'static str> {
        let banned = self.bans.bans_id(id);
        let off_list = self.mode == Mode::List && !self.is_approved(id);
        let Some(c) = self.members.get_mut(&k) else { return Err(GONE) };
        c.heard = now;
        let why = if c.state != State::Connected {
            BAD_CHECK_IN
        } else {
            c.id = Some(id.to_string());
            if banned {
                DENIED
            } else if off_list {
                NOT_LISTED
            } else {
                c.state = State::Hello;
                return Ok(());
            }
        };
        self.let_go(k, Some(why));
        Err(why)
    }

    /// The key is proved: one already here under the same id is refused REPLACED and let go first (and, if it was
    /// listed, every other member of its group is sent `RelayGone`). Before a hello: BAD_CHECK_IN.
    pub fn proved(&mut self, k: MemberKey, now: f64) {
        let Some(c) = self.members.get_mut(&k) else { return };
        c.heard = now;
        if c.state != State::Hello {
            self.let_go(k, Some(BAD_CHECK_IN));
            return;
        }
        c.state = State::Proved;
        let id = c.id.clone();
        let old: Vec<MemberKey> =
            self.members.iter().filter(|(o, c)| **o != k && c.proved() && c.id == id).map(|(o, _)| *o).collect();
        for o in old {
            self.let_go(o, Some(REPLACED));
        }
    }

    /// Its check-in: Ok((host, port)) for the server to resolve (an IPv4 literal is its own answer, and the server
    /// calls `resolved` with it at once; a host name comes back lowercase, a trailing dot dropped). Err, the member
    /// refused and let go: BAD_CHECK_IN (before `proved`, a second check-in, or not a `parse_address` address),
    /// OTHER_WIRE, NO_IPV6 for an IPv6 literal, DENIED for a banned host name.
    pub fn check_in(
        &mut self,
        k: MemberKey,
        address: &str,
        wire: u32,
        proto: u32,
        c: Counts,
        now: f64,
    ) -> Result<(String, u16), &'static str> {
        let Some(m) = self.members.get_mut(&k) else { return Err(GONE) };
        m.heard = now;
        let read = if m.state != State::Proved {
            Err(BAD_CHECK_IN)
        } else if wire != self.wire {
            Err(OTHER_WIRE)
        } else {
            read_address(address, &self.bans)
        };
        match read {
            Ok((host, named, port)) => {
                m.check_in = Some(CheckIn { host: host.clone(), named, port, proto });
                m.counts = Some(c);
                m.checks = 1;
                m.state = State::Lookup;
                Ok((host, port))
            }
            Err(why) => {
                self.let_go(k, Some(why));
                Err(why)
            }
        }
    }

    /// What the name resolved to (its first IPv4 address; the server sends Err(NO_IPV6) itself when there is none).
    /// Ok(the address to check). Err, refused and let go: DENIED for a banned IP; NEVER; NOT_PUBLIC unless an
    /// approved entry of this id has this address (its `host:port` equal, host case ignored, to what the check-in
    /// named, or to `ip:port`). Err(GONE), nothing done, when no lookup of a check is out for it.
    pub fn resolved(&mut self, k: MemberKey, ip: Ipv4Addr, _now: f64) -> Result<SocketAddrV4, &'static str> {
        let Some(c) = self.members.get(&k) else { return Err(GONE) };
        let (State::Lookup, Some(check_in)) = (c.state, &c.check_in) else { return Err(GONE) };
        let at = SocketAddrV4::new(ip, check_in.port);
        if let Err(why) = self.may_check(c, ip) {
            self.let_go(k, Some(why));
            return Err(why);
        }
        self.members[&k].state = State::Dial(at);
        Ok(at)
    }

    /// The address check's outcome. Proved: listed at `ip:port` (DENIED if that IP was banned meanwhile); it is sent
    /// a `RelayUp` for each member of its group, and each of those a `RelayUp` of it. OtherKey: refused OTHER_ADDRESS
    /// at once. NoAnswer: checked again later (`due`), within `checks` and `list_ms`.
    pub fn verified(&mut self, k: MemberKey, p: Proof, now: f64) {
        let Some(State::Dial(at)) = self.members.get(&k).map(|c| c.state) else { return };
        match p {
            // A ban added while the check was out holds it too.
            Proof::Proved if self.bans.bans_ip(*at.ip()) => self.let_go(k, Some(DENIED)),
            Proof::Proved => self.list(k, at, now),
            Proof::OtherKey => self.let_go(k, Some(OTHER_ADDRESS)),
            Proof::NoAnswer => self.check_failed(k, now),
        }
    }

    /// A name lookup that failed (no answer; not "no IPv4 address", which the server refuses NO_IPV6): a check's as
    /// NoAnswer; a refresh's keeps the listed address until the next refresh.
    pub fn unresolved(&mut self, k: MemberKey, now: f64) {
        let Some(c) = self.members.get_mut(&k) else { return };
        match c.state {
            State::Lookup => self.check_failed(k, now),
            State::Listed { at, refresh: Refresh::Lookup } => {
                c.state = State::Listed { at, refresh: Refresh::Due(now + self.limits.refresh_ms) };
            }
            _ => {}
        }
    }

    /// The checks and refreshes due now, in the order of the connections. Each is handed out once: the member is
    /// not handed out again until its answer comes, through `resolved` and `verified` (a check) or `refreshed` and
    /// `moved` (a refresh), or `unresolved` for either.
    pub fn due(&mut self, now: f64) -> Vec<Due> {
        let mut out = Vec::new();
        for (key, c) in &mut self.members {
            let Some(check_in) = &c.check_in else { continue };
            let (host, port) = (check_in.host.clone(), check_in.port);
            match c.state {
                State::Wait(when) if when <= now => {
                    c.state = State::Lookup;
                    c.checks += 1;
                    out.push(Due::Check { key: *key, host, port });
                }
                State::Listed { at, refresh: Refresh::Due(when) } if when <= now => {
                    c.state = State::Listed { at, refresh: Refresh::Lookup };
                    out.push(Due::Refresh { key: *key, host, port });
                }
                _ => {}
            }
        }
        out
    }

    /// A refresh's answer. None: the same IP (nothing to do) or the member let go (DENIED for a banned IP; NEVER;
    /// NOT_PUBLIC as at `resolved`). Some: the new address to prove there.
    pub fn refreshed(&mut self, k: MemberKey, ip: Ipv4Addr, now: f64) -> Option<SocketAddrV4> {
        let c = self.members.get(&k)?;
        let State::Listed { at, refresh: Refresh::Lookup } = c.state else { return None };
        if let Err(why) = self.may_check(c, ip) {
            self.let_go(k, Some(why));
            return None;
        }
        let c = &mut self.members[&k];
        if ip == *at.ip() {
            c.state = State::Listed { at, refresh: Refresh::Due(now + self.limits.refresh_ms) };
            return None;
        }
        let to = SocketAddrV4::new(ip, at.port());
        c.state = State::Listed { at, refresh: Refresh::Dial(to) };
        Some(to)
    }

    /// That proof's outcome. Proved: the listed address becomes it (DENIED if that IP was banned meanwhile), its group
    /// sent `RelayUp`. OtherKey: refused OTHER_ADDRESS. NoAnswer: the old address kept until the next refresh.
    pub fn moved(&mut self, k: MemberKey, at: SocketAddrV4, p: Proof, now: f64) {
        let Some(c) = self.members.get_mut(&k) else { return };
        let State::Listed { at: old, refresh: Refresh::Dial(to) } = c.state else { return };
        if to != at {
            return;
        }
        let next = Refresh::Due(now + self.limits.refresh_ms);
        match p {
            Proof::Proved if self.bans.bans_ip(*at.ip()) => self.let_go(k, Some(DENIED)),
            Proof::Proved => {
                c.state = State::Listed { at, refresh: next };
                let line = format!("listed {} at {at}", c.who());
                (self.log)(&line);
                self.tell_again(k);
            }
            Proof::OtherKey => self.let_go(k, Some(OTHER_ADDRESS)),
            Proof::NoAnswer => c.state = State::Listed { at: old, refresh: next },
        }
    }

    /// A beat: answered `Beat`; the counts kept as sent; nobody else sent anything. Before its check-in:
    /// BAD_CHECK_IN.
    pub fn beat(&mut self, k: MemberKey, c: Counts, now: f64) {
        let Some(m) = self.members.get_mut(&k) else { return };
        m.heard = now;
        if m.check_in.is_none() {
            self.let_go(k, Some(BAD_CHECK_IN));
            return;
        }
        m.counts = Some(c);
        if !m.m.send(&FromRegistry::Beat {}) {
            self.let_go(k, None);
        }
    }

    /// The connection closed. If it was listed, its group is sent `RelayGone`.
    pub fn leave(&mut self, k: MemberKey, _now: f64) {
        self.let_go(k, None);
    }

    /// SILENT for a member that sent nothing for `silent_ms`; NOT_IN_TIME for one not listed `list_ms` after its
    /// connection (one out of checks is let go at its last check's failure).
    pub fn expire(&mut self, now: f64) {
        let mut out = Vec::new();
        for (k, c) in &self.members {
            if now - c.heard >= self.limits.silent_ms {
                out.push((*k, SILENT));
            } else if c.listed_at().is_none() && now - c.since >= self.limits.list_ms {
                out.push((*k, NOT_IN_TIME));
            }
        }
        for (k, why) in out {
            self.let_go(k, Some(why));
        }
    }

    /// Every listed member of that protocol, in the order of their connections.
    pub fn relays(&self, proto: u32) -> Vec<RelayEntry> {
        self.members.values().filter(|c| c.group() == Some(proto)).filter_map(|c| self.entry(c)).collect()
    }

    /// Whether `at` may be dialed now (a check-in's check, a refresh's, a submission's): false past
    /// `dials_per_minute` for that `ip:port`, and the dial is counted when true.
    pub fn may_dial_target(&mut self, at: SocketAddrV4, now: f64) -> bool {
        self.dials.get(&at.to_string(), now).take(1.0, now)
    }

    /// On the allow list (an entry of the same id replaced). A listed member of that id is sent again to its group
    /// with `approved: true`.
    pub fn approve(&mut self, a: Approved, _now: f64) {
        let id = a.id.clone();
        match self.approved.iter_mut().find(|e| e.id == a.id) {
            Some(e) => *e = a,
            None => self.approved.push(a),
        }
        self.tell_again_id(&id);
    }

    /// Off the allow list (false: no such id). In `List` mode its member is refused NOT_LISTED and let go; in `Open`
    /// mode its group is sent its entry again with `approved: false`.
    pub fn unapprove(&mut self, id: &str, _now: f64) -> bool {
        let before = self.approved.len();
        self.approved.retain(|e| e.id != id);
        if self.approved.len() == before {
            return false;
        }
        match self.mode {
            Mode::List => {
                let held: Vec<MemberKey> =
                    self.members.iter().filter(|(_, c)| c.id.as_deref() == Some(id)).map(|(k, _)| *k).collect();
                for k in held {
                    self.let_go(k, Some(NOT_LISTED));
                }
            }
            Mode::Open => self.tell_again_id(id),
        }
        true
    }

    /// False (nothing changed): already there. Every member it holds refused DENIED and let go, its group sent
    /// `RelayGone`: an `Id` ban by its id, a `Host` ban by the host name its check-in named, an address ban by its
    /// source IP or the IP it is listed at.
    pub fn ban(&mut self, b: Ban, _now: f64) -> bool {
        if !self.bans.add(b.clone()) {
            return false;
        }
        let one = Bans::new(vec![b.clone()]);
        let holds = |c: &Conn| match &b {
            Ban::Id(id) => c.id.as_ref() == Some(id),
            Ban::Host(host) => c.check_in.as_ref().is_some_and(|ci| ci.named && ci.host == host_key(host)),
            Ban::Ip(_) | Ban::Range(..) | Ban::Cidr(..) => {
                one.bans_ip(c.source) || c.listed_at().is_some_and(|at| one.bans_ip(*at.ip()))
            }
        };
        let held: Vec<MemberKey> = self.members.iter().filter(|(_, c)| holds(c)).map(|(k, _)| *k).collect();
        for k in held {
            self.let_go(k, Some(DENIED));
        }
        true
    }

    /// False: not there.
    pub fn unban(&mut self, b: &Ban) -> bool {
        self.bans.remove(b)
    }

    pub fn approved(&self) -> &[Approved] {
        &self.approved
    }

    pub fn bans(&self) -> &[Ban] {
        self.bans.list()
    }

    /// Every connection, in order.
    pub fn seen(&self) -> Vec<Seen> {
        let seen = |(key, c): (&MemberKey, &Conn)| {
            let address = match c.state {
                State::Listed { at, .. } | State::Dial(at) => Some(at.to_string()),
                _ => None,
            };
            Seen {
                key: *key,
                source: c.source,
                id: c.id.clone(),
                address,
                listed: c.listed_at().is_some(),
                approved: c.id.as_deref().is_some_and(|id| self.is_approved(id)),
                counts: c.counts,
            }
        };
        self.members.iter().map(seen).collect()
    }

    fn is_approved(&self, id: &str) -> bool {
        self.approved.iter().any(|e| e.id == id)
    }

    /// Whether `c` may be checked at `ip`: not a banned IP, and one the rules let it name (a private one only when an
    /// approved entry of its id names that address).
    fn may_check(&self, c: &Conn, ip: Ipv4Addr) -> Result<(), &'static str> {
        if self.bans.bans_ip(ip) {
            return Err(DENIED);
        }
        let Some(check_in) = &c.check_in else { return Err(BAD_CHECK_IN) };
        let ip_text = ip.to_string();
        let names = |address: &str| {
            parse_address(address).is_some_and(|a| {
                let host = host_key(&a.host);
                a.port == check_in.port && (host == check_in.host || host == ip_text)
            })
        };
        let configured =
            self.approved.iter().any(|e| c.id.as_ref() == Some(&e.id) && e.address.as_deref().is_some_and(names));
        may_dial(IpAddr::V4(ip), if configured { Source::Config } else { Source::Public })
    }

    /// Its entry in the relay list, when listed.
    fn entry(&self, c: &Conn) -> Option<RelayEntry> {
        let at = c.listed_at()?;
        let id = c.id.clone()?;
        let approved = self.approved.iter().find(|e| e.id == id);
        Some(RelayEntry {
            address: at.to_string(),
            name: approved.and_then(|e| e.name.clone()),
            approved: approved.is_some(),
            id,
        })
    }

    /// The check proved `k` at `at`: listed, told of its group, and its group of it.
    fn list(&mut self, k: MemberKey, at: SocketAddrV4, now: f64) {
        let c = &mut self.members[&k];
        let Some(check_in) = &c.check_in else { return };
        let refresh = if check_in.named { Refresh::Due(now + self.limits.refresh_ms) } else { Refresh::Never };
        c.state = State::Listed { at, refresh };
        let line = format!("listed {} at {at}", c.who());
        (self.log)(&line);
        let c = &self.members[&k];
        let proto = c.group();
        let others: Vec<RelayEntry> = self
            .members
            .iter()
            .filter(|(o, oc)| **o != k && oc.group() == proto)
            .filter_map(|(_, oc)| self.entry(oc))
            .collect();
        let mut lost = Vec::new();
        let c = &mut self.members[&k];
        for relay in others {
            if !c.m.send(&FromRegistry::RelayUp { relay }) {
                lost.push(k);
                break;
            }
        }
        lost.extend(self.tell_group(k));
        for o in lost {
            self.let_go(o, None);
        }
    }

    /// Its group sent its entry again (a new address, or a change on the allow list).
    fn tell_again(&mut self, k: MemberKey) {
        for o in self.tell_group(k) {
            self.let_go(o, None);
        }
    }

    fn tell_again_id(&mut self, id: &str) {
        let listed = self.members.iter().find(|(_, c)| c.listed_at().is_some() && c.id.as_deref() == Some(id));
        if let Some((k, _)) = listed {
            self.tell_again(*k);
        }
    }

    /// Every other member of `k`'s group sent `k`'s entry: those whose connections can take no more.
    fn tell_group(&mut self, k: MemberKey) -> Vec<MemberKey> {
        let Some(c) = self.members.get(&k) else { return Vec::new() };
        let (Some(proto), Some(relay)) = (c.group(), self.entry(c)) else { return Vec::new() };
        let up = FromRegistry::RelayUp { relay };
        let mut lost = Vec::new();
        for (o, oc) in &mut self.members {
            if *o != k && oc.group() == Some(proto) && !oc.m.send(&up) {
                lost.push(*o);
            }
        }
        lost
    }

    /// `k` gone: refused `why` (once), or, with none, left. A listed one's group is sent `RelayGone`, and a member
    /// whose connection can take no more of that is let go in turn.
    fn let_go(&mut self, k: MemberKey, why: Option<&'static str>) {
        let mut queue = vec![(k, why)];
        while let Some((k, why)) = queue.pop() {
            let Some(mut c) = self.members.shift_remove(&k) else { continue };
            let group = c.group();
            if let Some(why) = why {
                c.m.refuse(why);
                (self.log)(&format!("refused {}: {why}", c.who()));
            } else if group.is_some() {
                (self.log)(&format!("gone {}", c.who()));
            }
            let (Some(proto), Some(id)) = (group, c.id) else { continue };
            let gone = FromRegistry::RelayGone { id };
            for (o, oc) in &mut self.members {
                if oc.group() == Some(proto) && !oc.m.send(&gone) {
                    queue.push((*o, None));
                }
            }
        }
    }

    /// A check of `k` failed: the next one due after a wait doubling with each failure, or, out of checks,
    /// NOT_IN_TIME.
    fn check_failed(&mut self, k: MemberKey, now: f64) {
        let Some(c) = self.members.get_mut(&k) else { return };
        if c.checks >= self.limits.checks {
            self.let_go(k, Some(NOT_IN_TIME));
            return;
        }
        let doublings = i32::try_from(c.checks.saturating_sub(1)).unwrap_or(i32::MAX);
        c.state = State::Wait(now + self.limits.recheck_ms * 2f64.powi(doublings));
    }
}

/// A check-in's address as (host, named, port): an IPv4 literal as its text (`named` false), a host name as bans
/// keep it. Err: BAD_CHECK_IN, NO_IPV6, or DENIED for a banned host name.
fn read_address(address: &str, bans: &Bans) -> Result<(String, bool, u16), &'static str> {
    let a = parse_address(address).ok_or(BAD_CHECK_IN)?;
    if a.host.parse::<Ipv6Addr>().is_ok() {
        return Err(NO_IPV6);
    }
    if let Ok(ip) = a.host.parse::<Ipv4Addr>() {
        return Ok((ip.to_string(), false, a.port));
    }
    let host = host_key(&a.host);
    if bans.bans_host(&host) {
        return Err(DENIED);
    }
    Ok((host, true, a.port))
}
