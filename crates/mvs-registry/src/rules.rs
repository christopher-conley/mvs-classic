//! The registry's rules over addresses and bans: which IPv4 addresses it may dial, and from where it may be told
//! them; and the bans (a relay's id, an address, a range, a block, a host name) and what each holds.

use mvs_protocol::relay_wire::is_key_id;
use std::net::{IpAddr, Ipv4Addr};

/// Where an address to dial came from: the admin's config may name any address that is not always refused; a
/// check-in or the web page only a public one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Config,
    Public,
}

pub const NO_IPV6: &str = "IPv6 addresses are not taken";
pub const NOT_PUBLIC: &str = "a private address is taken only from the registry's config";
pub const NEVER: &str = "that address is never dialed";

/// Whether the registry may dial `ip`. Always refused (NEVER): 0.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4,
/// 240.0.0.0/4 (255.255.255.255 with it). Private (NOT_PUBLIC unless `Source::Config`): 10/8, 172.16/12,
/// 192.168/16, 100.64/10, 127/8. Any IPv6 address, an IPv4-mapped one too: NO_IPV6.
pub fn may_dial(ip: IpAddr, from: Source) -> Result<(), &'static str> {
    let IpAddr::V4(ip) = ip else { return Err(NO_IPV6) };
    let [a, b, ..] = ip.octets();
    // 224/4 and 240/4 together are every first octet from 224 up.
    if a == 0 || (a, b) == (169, 254) || a >= 224 {
        return Err(NEVER);
    }
    let private = a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a, b) == (192, 168)
        || (a == 100 && (64..=127).contains(&b))
        || a == 127;
    if private && from == Source::Public { Err(NOT_PUBLIC) } else { Ok(()) }
}

/// One ban: a relay's id, an address, a range of addresses (both ends included), a block (its host bits clear), or a
/// host name (lowercase, no trailing dot).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ban {
    Id(String),
    Ip(Ipv4Addr),
    Range(Ipv4Addr, Ipv4Addr),
    Cidr(Ipv4Addr, u8),
    Host(String),
}

impl Ban {
    /// One ban as the config, the state file and the admin page write it: a relay id (`is_key_id`); `a.b.c.d`;
    /// `a.b.c.d-e.f.g.h` (spaces around the dash allowed; the first not above the second; both ends included);
    /// `a.b.c.d/n` (n 0 to 32; the host bits are cleared, so `10.18.18.5/27` is `10.18.18.0/27`); else a host
    /// name (letters, digits, dots, hyphens; kept lowercase, a trailing dot dropped). Err names what is wrong.
    pub fn parse(text: &str) -> Result<Ban, String> {
        if text.is_empty() {
            return Err("a ban is empty".into());
        }
        if is_key_id(text) {
            return Ok(Ban::Id(text.into()));
        }
        if let Some((ip, bits)) = text.split_once('/') {
            let ip: Ipv4Addr = ip.parse().map_err(|_| "a block's address is not an IPv4 address".to_string())?;
            let bits = match bits.parse::<u8>() {
                Ok(n) if n <= 32 => n,
                _ => return Err("a block's prefix length is a number from 0 to 32".into()),
            };
            return Ok(Ban::Cidr(Ipv4Addr::from_bits(ip.to_bits() & mask(bits)), bits));
        }
        if let Some((first, last)) = text.split_once('-')
            && let (Ok(first), Ok(last)) = (first.trim().parse::<Ipv4Addr>(), last.trim().parse::<Ipv4Addr>())
        {
            if first > last {
                return Err("a range's first address is above its last".into());
            }
            return Ok(Ban::Range(first, last));
        }
        if let Ok(ip) = text.parse::<Ipv4Addr>() {
            return Ok(Ban::Ip(ip));
        }
        let host = host_key(text);
        let labels_ok =
            host.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !labels_ok {
            return Err("not a relay id, an IPv4 address, a range, a block or a host name".into());
        }
        // A name whose last label is all digits is a mistyped address (`1.2.3`), not a host.
        if host.rsplit('.').next().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit())) {
            return Err("not a whole IPv4 address".into());
        }
        Ok(Ban::Host(host))
    }

    /// The form `parse` reads back to the same ban.
    pub fn text(&self) -> String {
        match self {
            Ban::Id(id) => id.clone(),
            Ban::Ip(ip) => ip.to_string(),
            Ban::Range(first, last) => format!("{first}-{last}"),
            Ban::Cidr(ip, bits) => format!("{ip}/{bits}"),
            Ban::Host(host) => host.clone(),
        }
    }
}

/// The mask of a `/bits` block's network part.
fn mask(bits: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0)
}

/// A host name as bans compare it: lowercase, a trailing dot dropped.
fn host_key(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// The bans in force, in the order added, each once.
#[derive(Clone, Debug, Default)]
pub struct Bans {
    bans: Vec<Ban>,
}

impl Bans {
    pub fn new(bans: Vec<Ban>) -> Bans {
        let mut out = Bans::default();
        for b in bans {
            out.add(b);
        }
        out
    }

    /// False: already there.
    pub fn add(&mut self, b: Ban) -> bool {
        if self.bans.contains(&b) {
            return false;
        }
        self.bans.push(b);
        true
    }

    /// False: not there.
    pub fn remove(&mut self, b: &Ban) -> bool {
        let before = self.bans.len();
        self.bans.retain(|x| x != b);
        self.bans.len() != before
    }

    /// In the order added.
    pub fn list(&self) -> &[Ban] {
        &self.bans
    }

    pub fn bans_id(&self, id: &str) -> bool {
        self.bans.iter().any(|b| matches!(b, Ban::Id(x) if x == id))
    }

    /// An `Ip`, a `Range` or a `Cidr` that holds `ip`.
    pub fn bans_ip(&self, ip: Ipv4Addr) -> bool {
        self.bans.iter().any(|b| match *b {
            Ban::Ip(x) => x == ip,
            Ban::Range(first, last) => (first..=last).contains(&ip),
            Ban::Cidr(net, bits) => ip.to_bits() & mask(bits) == net.to_bits(),
            Ban::Id(_) | Ban::Host(_) => false,
        })
    }

    /// Case and a trailing dot ignored.
    pub fn bans_host(&self, host: &str) -> bool {
        let host = host_key(host);
        self.bans.iter().any(|b| matches!(b, Ban::Host(x) if *x == host))
    }
}
