//! The address rules (which addresses the registry dials, from where) and the bans (each form, read and held).

use mvs_protocol::relay_wire::key_id;
use mvs_registry::rules::{Ban, Bans, NEVER, NO_IPV6, NOT_PUBLIC, Source, may_dial};
use std::net::{IpAddr, Ipv4Addr};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap_or_else(|_| panic!("{text} is an address"))
}

fn v4(text: &str) -> Ipv4Addr {
    text.parse().unwrap_or_else(|_| panic!("{text} is an IPv4 address"))
}

fn ban(text: &str) -> Ban {
    Ban::parse(text).unwrap_or_else(|e| panic!("{text} reads: {e}"))
}

#[test]
fn never_dialed() {
    for case in [
        "0.0.0.0",
        "0.255.255.255",
        "169.254.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
    ] {
        assert_eq!(may_dial(ip(case), Source::Config), Err(NEVER), "{case} from the config");
        assert_eq!(may_dial(ip(case), Source::Public), Err(NEVER), "{case} from the public");
    }
}

#[test]
fn private_only_from_the_config() {
    for case in [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
    ] {
        assert_eq!(may_dial(ip(case), Source::Config), Ok(()), "{case} from the config");
        assert_eq!(may_dial(ip(case), Source::Public), Err(NOT_PUBLIC), "{case} from the public");
    }
}

#[test]
fn the_neighbors_are_public() {
    for case in [
        "9.255.255.255",
        "11.0.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "1.1.1.1",
        "223.255.255.255",
    ] {
        assert_eq!(may_dial(ip(case), Source::Config), Ok(()), "{case} from the config");
        assert_eq!(may_dial(ip(case), Source::Public), Ok(()), "{case} from the public");
    }
}

#[test]
fn no_ipv6() {
    for case in ["::1", "2001:db8::1", "::ffff:10.0.0.1", "::ffff:1.1.1.1"] {
        assert_eq!(may_dial(ip(case), Source::Config), Err(NO_IPV6), "{case} from the config");
        assert_eq!(may_dial(ip(case), Source::Public), Err(NO_IPV6), "{case} from the public");
    }
}

#[test]
fn bans_read_each_form() {
    let id = key_id(&[1; 32]);
    let range = Ban::Range(v4("10.18.18.1"), v4("10.18.18.29"));
    let cidr = Ban::Cidr(v4("10.18.18.0"), 27);
    let cases = [
        (id.as_str(), Ban::Id(id.clone())),
        ("10.18.18.7", Ban::Ip(v4("10.18.18.7"))),
        ("10.18.18.1-10.18.18.29", range.clone()),
        ("10.18.18.1 - 10.18.18.29", range),
        ("10.18.18.0/27", cidr.clone()),
        ("10.18.18.5/27", cidr),
        ("Bad.Example.COM.", Ban::Host("bad.example.com".into())),
    ];
    for (case, want) in cases {
        let got = Ban::parse(case);
        assert_eq!(got, Ok(want.clone()), "{case}");
        assert_eq!(Ban::parse(&want.text()), Ok(want.clone()), "{case}'s text {}", want.text());
    }
}

#[test]
fn bad_bans_are_named() {
    for case in ["10.18.18.29-10.18.18.1", "10.0.0.0/33", "1.2.3", "a b", ""] {
        let got = Ban::parse(case);
        assert!(matches!(&got, Err(why) if !why.is_empty()), "{case:?} read as {got:?}");
    }
}

#[test]
fn a_range_holds_its_ends() {
    let bans = Bans::new(vec![ban("10.18.18.1-10.18.18.29")]);
    for (case, banned) in [("10.18.18.1", true), ("10.18.18.29", true), ("10.18.18.0", false), ("10.18.18.30", false)] {
        assert_eq!(bans.bans_ip(v4(case)), banned, "{case}");
    }
}

#[test]
fn a_cidr_holds_its_block() {
    let block = Bans::new(vec![ban("10.18.18.0/27")]);
    for (case, banned) in [("10.18.18.0", true), ("10.18.18.31", true), ("10.18.18.32", false)] {
        assert_eq!(block.bans_ip(v4(case)), banned, "/27: {case}");
    }
    let all = Bans::new(vec![ban("0.0.0.0/0")]);
    for case in ["0.0.0.0", "1.1.1.1", "10.18.18.32", "255.255.255.255"] {
        assert!(all.bans_ip(v4(case)), "/0: {case}");
    }
    let one = Bans::new(vec![ban("10.18.18.5/32")]);
    for (case, banned) in [("10.18.18.5", true), ("10.18.18.4", false), ("10.18.18.6", false)] {
        assert_eq!(one.bans_ip(v4(case)), banned, "/32: {case}");
    }
}

#[test]
fn a_host_ban_ignores_case_and_the_dot() {
    let bans = Bans::new(vec![ban("bad.example.com")]);
    for (case, banned) in [
        ("bad.example.com", true),
        ("BAD.Example.Com", true),
        ("bad.example.com.", true),
        ("good.example.com", false),
        ("example.com", false),
    ] {
        assert_eq!(bans.bans_host(case), banned, "{case}");
    }
}

#[test]
fn an_id_ban_is_exact() {
    let banned = key_id(&[1; 32]);
    let other = key_id(&[2; 32]);
    let mut bans = Bans::new(vec![ban(&banned)]);
    assert!(bans.bans_id(&banned));
    assert!(!bans.bans_id(&other), "another id");
    assert!(!bans.add(Ban::Id(banned.clone())), "already there");
    assert!(bans.add(Ban::Id(other.clone())));
    assert_eq!(bans.list(), [Ban::Id(banned.clone()), Ban::Id(other.clone())], "in the order added");
    assert!(bans.remove(&Ban::Id(other.clone())));
    assert!(!bans.remove(&Ban::Id(other.clone())), "not there");
    assert!(!bans.bans_id(&other));
}
