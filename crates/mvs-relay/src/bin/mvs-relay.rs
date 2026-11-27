//! mvs-relay: a relay on one port, TCP and UDP. Its config (mvs-relay.json) and key (mvs-relay.key)
//! are beside the executable; --config names another config file, and the key goes beside that one. Both are made
//! on the first run; a config without its key beside it stops the relay (the key is the relay's id, which releases
//! may be pinned to: it is restored from its backup, never made anew without its owner knowing).
//!
//!   mvs-relay [--port <n>] [--host <ip>] [--config <file>] [--version]
//!
//! --host listens on that address alone (a local test relay: `--host 127.0.0.1`, so Windows asks for no firewall
//! rule); the config's host otherwise, every address when empty.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::Poll;
use std::time::{SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use mvs_protocol::registry_wire::REGISTRY_PORT;
use mvs_protocol::relay_wire::{RELAY_PORT, RELAY_WIRE_VERSION, is_key_id, parse_address};
use mvs_relay::limits::{DEFAULT_LIMITS, MIN_PACKET_BYTES, RelayLimits};
use mvs_relay::server::{Options, RegistryOptions, start_relay};
use serde::de::IgnoredAny;
use serde_json::{Value, json};

/// The config file's settings.
struct Config {
    /// The port for TCP and UDP.
    port: u16,
    /// The address to listen on: empty for all of this PC's (IPv4 and IPv6).
    host: String,
    limits: RelayLimits,
    /// The registry it checks in to (the config's `registry` block), if any.
    registry: Option<RegistryOptions>,
    /// The top-level fields it does not know, in the config's order: ignored, and named on stderr.
    unknown: Vec<String>,
}

/// `YYYY-MM-DD HH:MM:SSZ`, UTC.
fn stamp() -> String {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
    // the civil date of a day number (Howard Hinnant's days_from_civil, inverted)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z", secs / 3600, secs / 60 % 60, secs % 60)
}

fn say(line: &str) {
    println!("{} {line}", stamp());
}

fn fail(why: &str) -> ! {
    eprintln!("mvs-relay: {why}");
    std::process::exit(1);
}

/// The value after `name` on the command line (its first), if it is there.
fn arg(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    match args.get(i + 1) {
        Some(v) if !v.starts_with("--") => Some(v.clone()),
        _ => fail(&format!("{name} needs a value")),
    }
}

fn port(v: &Value, what: &str) -> u16 {
    let n = match v {
        Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => s.parse::<f64>().ok(),
        Value::Number(n) => n.as_f64(),
        _ => None,
    };
    match n {
        Some(n) if n.fract() == 0.0 && (1.0..=65535.0).contains(&n) => n as u16,
        _ => fail(&format!("{what} is not a port (1 to 65535)")),
    }
}

/// A limit as JSON writes it: a whole number without its point.
fn number(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 9007199254740992.0 { json!(v as i64) } else { json!(v) }
}

/// The defaults as JSON.stringify(DEFAULTS, null, 2) writes them: the keys in the config's order (serde_json's map
/// would sort them).
fn defaults_text() -> String {
    let mut d = DEFAULT_LIMITS;
    let limits: Vec<String> = d.fields_mut().into_iter().map(|(k, v)| format!("    \"{k}\": {}", number(*v))).collect();
    format!("{{\n  \"port\": {RELAY_PORT},\n  \"host\": \"\",\n  \"limits\": {{\n{}\n  }}\n}}\n", limits.join(",\n"))
}

/// The fields of a config's `registry` block.
const REGISTRY_FIELDS: [&str; 4] = ["address", "id", "public", "afterMs"];
/// The top-level fields `read_config` reads.
const CONFIG_FIELDS: [&str; 4] = ["port", "host", "limits", "registry"];

/// A registry's address as the link dials it, `host:port`: the port [`REGISTRY_PORT`] when the text names none
/// (`parse_address` fills in the relay's port, and its answer does not say whether one was written). None when the
/// text is not an address.
fn registry_address(text: &str) -> Option<String> {
    let a = parse_address(text)?;
    let s = text.trim();
    // (a bracketed IPv6 host has its port after the bracket; an unbracketed one has no port, only its colons)
    let named = if s.starts_with('[') { s.contains("]:") } else { s.matches(':').count() == 1 };
    let port = if named { a.port } else { REGISTRY_PORT };
    Some(if a.host.contains(':') { format!("[{}]:{port}", a.host) } else { format!("{}:{port}", a.host) })
}

/// The config's `registry` block, `file` the config's name in a mistake's reason: None when there is none. A mistake
/// in it (a field not known, an id that is not one, an address that is not one) stops the program, as a bad limit
/// does.
fn read_registry(config: &Value, file: &str) -> Result<Option<RegistryOptions>, String> {
    let f = file;
    let Some(block) = config.get("registry") else { return Ok(None) };
    let Value::Object(b) = block else { return Err(format!("{f}: registry is not an object")) };
    if let Some(k) = b.keys().find(|k| !REGISTRY_FIELDS.contains(&k.as_str())) {
        return Err(format!("{f}: registry.{k} is not a registry field ({})", REGISTRY_FIELDS.join(", ")));
    }
    let text = |k: &str| b.get(k).and_then(Value::as_str);
    let address = text("address")
        .and_then(registry_address)
        .ok_or_else(|| format!("{f}: registry.address is not an address (host[:port])"))?;
    let id = text("id").filter(|s| is_key_id(s)).ok_or_else(|| format!("{f}: registry.id is not a relay id"))?;
    let public = text("public")
        .filter(|s| parse_address(s).is_some())
        .ok_or_else(|| format!("{f}: registry.public is not an address (host[:port])"))?;
    let mut o = RegistryOptions::new(&address, id, public);
    if let Some(v) = b.get("afterMs") {
        match v.as_f64() {
            Some(n) if n.is_finite() && n >= 0.0 => o.after_ms = n,
            _ => return Err(format!("{f}: registry.afterMs is not a number of 0 or more")),
        }
    }
    Ok(Some(o))
}

/// The top-level fields of a config's text that `read_config` does not read, in the text's order (a `Value`'s map
/// sorts its keys, so the text is read again in order).
fn unknown_fields(text: &str) -> Vec<String> {
    serde_json::from_str::<IndexMap<String, IgnoredAny>>(text)
        .map(|m| m.into_keys().filter(|k| !CONFIG_FIELDS.contains(&k.as_str())).collect())
        .unwrap_or_default()
}

/// The config file's, over the defaults; written with the defaults when there is none.
fn read_config(file: &Path) -> Config {
    let f = file.display();
    let mut out =
        Config { port: RELAY_PORT, host: String::new(), limits: DEFAULT_LIMITS, registry: None, unknown: Vec::new() };
    if !file.exists() {
        if let Err(e) = std::fs::write(file, defaults_text()) {
            fail(&format!("could not write {f}: {e}"));
        }
        say(&format!("wrote {f} with the defaults"));
        return out;
    }
    let text = std::fs::read_to_string(file).unwrap_or_else(|e| fail(&format!("could not read {f}: {e}")));
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let raw: Value = serde_json::from_str(text).unwrap_or_else(|e| fail(&format!("{f} is not JSON: {e}")));
    let Value::Object(c) = &raw else { fail(&format!("{f} is not a JSON object")) };
    if let Some(p) = c.get("port") {
        out.port = port(p, &format!("{f}: port"));
    }
    if let Some(h) = c.get("host") {
        let Value::String(h) = h else { fail(&format!("{f}: host is not text")) };
        out.host = h.clone();
    }
    if let Some(l) = c.get("limits") {
        let entries: Vec<(String, &Value)> = match l {
            Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v)).collect(),
            Value::Array(a) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v)).collect(),
            _ => fail(&format!("{f}: limits is not an object")),
        };
        let names: Vec<&str> = DEFAULT_LIMITS.clone().fields_mut().map(|(k, _)| k).to_vec();
        for (k, v) in entries {
            let Some((_, slot)) = out.limits.fields_mut().into_iter().find(|(n, _)| *n == k) else {
                fail(&format!("{f}: limits.{k} is not a limit ({})", names.join(", ")))
            };
            match v.as_f64() {
                Some(n) if n.is_finite() && n > 0.0 => *slot = n,
                _ => fail(&format!("{f}: limits.{k} is not a number above 0")),
            }
        }
        // (a host core's message goes in pieces of packetBytes, each its frame byte and a byte of the message)
        if out.limits.packet_bytes < MIN_PACKET_BYTES || out.limits.frame_bytes < MIN_PACKET_BYTES + 5.0 {
            fail(&format!(
                "{f}: limits.packetBytes is under {MIN_PACKET_BYTES} or limits.frameBytes under {}",
                MIN_PACKET_BYTES + 5.0
            ));
        }
    }
    out.registry = read_registry(&raw, &f.to_string()).unwrap_or_else(|e| fail(&e));
    out.unknown = unknown_fields(text);
    out
}

/// The address this PC sends from toward `to` (a UDP socket's connect sends nothing).
fn outward(bind: IpAddr, to: IpAddr) -> Option<IpAddr> {
    let s = UdpSocket::bind(SocketAddr::new(bind, 0)).ok()?;
    s.connect(SocketAddr::new(to, 53)).ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// This PC's addresses others may reach it on: IPv4, and IPv6 but its link-local ones.
// Deviation: Node lists every interface's addresses; std has no interface list, so this names the address of each
// family's default route (the one players reach on most PCs).
fn addresses(host: &str, p: u16) -> Vec<String> {
    if !host.is_empty() && host != "::" && host != "0.0.0.0" {
        return vec![if host.contains(':') { format!("[{host}]:{p}") } else { format!("{host}:{p}") }];
    }
    let mut out = Vec::new();
    if let Some(a) =
        outward(Ipv4Addr::UNSPECIFIED.into(), Ipv4Addr::new(192, 0, 2, 1).into()).filter(|a| !a.is_loopback())
    {
        out.push(format!("{a}:{p}"));
    }
    if host != "0.0.0.0"
        && let Some(a) = outward(Ipv6Addr::UNSPECIFIED.into(), "2001:db8::1".parse().expect("an address"))
            .filter(|a| !a.is_loopback() && !a.to_string().to_lowercase().starts_with("fe80"))
    {
        out.push(format!("[{a}]:{p}"));
    }
    out
}

/// The next stop signal's name: Ctrl+C (SIGINT), or SIGTERM where there is one.
async fn stop_signal() -> &'static str {
    let mut int = pin!(tokio::signal::ctrl_c());
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).ok();
        std::future::poll_fn(|cx| {
            if int.as_mut().poll(cx).is_ready() {
                return Poll::Ready("SIGINT");
            }
            match term.as_mut().map(|t| t.poll_recv(cx)) {
                Some(Poll::Ready(_)) => Poll::Ready("SIGTERM"),
                _ => Poll::Pending,
            }
        })
        .await
    }
    #[cfg(not(unix))]
    {
        std::future::poll_fn(|cx| int.as_mut().poll(cx).map(|_| "SIGINT")).await
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let version = mvs_release::VERSION;
    if args.iter().any(|a| a == "--version") {
        println!("mvs-relay {version} (wire {RELAY_WIRE_VERSION})");
        return;
    }
    let here = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_default();
    let config_file = match arg(&args, "--config") {
        Some(c) => std::path::absolute(&c).unwrap_or_else(|_| PathBuf::from(c)),
        None => here.join("mvs-relay.json"),
    };
    let key_file = config_file.parent().map(|d| d.join("mvs-relay.key")).unwrap_or_else(|| "mvs-relay.key".into());
    if config_file.exists() && !key_file.exists() {
        fail(&format!(
            "{} is there but its key {} is not: restore the key from backup (a new key is a new relay id, which the releases pinned to this relay refuse); delete the config to start as a new relay",
            config_file.display(),
            key_file.display()
        ));
    }
    // (the key first: a first run that fails after it never leaves a config without its key)
    if let Err(e) = mvs_relay::server::load_key(Some(&key_file)) {
        fail(&format!("could not make or read the key {}: {e}", key_file.display()));
    }
    let mut config = read_config(&config_file);
    for k in &config.unknown {
        eprintln!("mvs-relay: {}: unknown field {k:?} is ignored", config_file.display());
    }
    if let Some(p) = arg(&args, "--port") {
        config.port = port(&Value::String(p), "--port");
    }
    if let Some(h) = arg(&args, "--host") {
        config.host = h;
    }

    // Every connection's and datagram's handling is guarded in the server (a panic there closes that connection), and
    // a referee's in the core. A panic is logged by where it was, never by its message, which may hold a client's text.
    std::panic::set_hook(Box::new(|p| {
        let at = p.location().map(|l| format!(" at {}:{}", l.file(), l.line())).unwrap_or_default();
        say(&format!("panic{at}"));
    }));

    let rt =
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap_or_else(|e| fail(&e.to_string()));
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        let o = Options {
            port: config.port,
            host: config.host.clone(),
            key_file: Some(key_file),
            limits: config.limits.clone(),
            log: Some(Box::new(say)),
            registry: config.registry.clone(),
            ..Options::default()
        };
        let relay = match start_relay(o) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                fail(&format!("port {} is in use by another program (--port picks another)", config.port))
            }
            Err(e) => fail(&format!("could not listen on port {}: {e}", config.port)),
        };
        say(&format!(
            "mvs-relay {version} (wire {RELAY_WIRE_VERSION}), relay id {}, port {} (TCP and UDP)",
            relay.id, relay.port
        ));
        say(&format!("config {}", config_file.display()));
        for a in addresses(&config.host, relay.port) {
            say(&format!("listening on {a}"));
        }
        // (the program touches no router: its owner forwards the port by hand)
        say(&format!(
            "players connect to this PC's outside address and port {}; behind a router, forward that port (TCP and UDP) to this PC. Ctrl+C stops",
            relay.port
        ));
        let first = stop_signal().await;
        say(&format!("{first}: stopping"));
        let mut closing = pin!(relay.close());
        let mut again = pin!(stop_signal());
        let code = std::future::poll_fn(|cx| {
            if closing.as_mut().poll(cx).is_ready() {
                return Poll::Ready(0);
            }
            again.as_mut().poll(cx).map(|_| 1)
        })
        .await;
        std::process::exit(code);
    });
}

#[cfg(test)]
mod read_registry {
    use super::*;

    const ID: &str = "r0123456789abcdef0123456789abcdef";

    fn read(v: Value) -> Result<Option<RegistryOptions>, String> {
        read_registry(&v, "c.json")
    }

    fn whole() -> Value {
        json!({ "address": "reg.example:7000", "id": ID, "public": "relay.example:7777", "afterMs": 5000 })
    }

    /// The `Err` of `registry` set to `block`, which must name `field`.
    fn names(block: Value, field: &str) {
        let e = read(json!({ "registry": block })).expect_err("a mistake stops the program");
        assert!(e.starts_with("c.json: "), "{e}");
        assert!(e.contains(field), "{e} names {field}");
    }

    #[test]
    fn no_block_is_no_registry() {
        assert_eq!(read(json!({ "port": 7777 })), Ok(None));
    }

    #[test]
    fn a_whole_block_reads() {
        let r = read(json!({ "registry": whole() })).unwrap().expect("a registry");
        let mut want = RegistryOptions::new("reg.example:7000", ID, "relay.example:7777");
        want.after_ms = 5000.0;
        assert_eq!(r, want);
    }

    #[test]
    fn after_ms_defaults_to_20000() {
        let r = read(json!({ "registry": { "address": "reg.example", "id": ID, "public": "relay.example" } }));
        assert_eq!(r.unwrap().expect("a registry").after_ms, 20000.0);
    }

    #[test]
    fn an_address_without_a_port_takes_the_registry_port() {
        let port = |a: &str| {
            let r = read(json!({ "registry": { "address": a, "id": ID, "public": "relay.example" } }));
            let r = r.unwrap().expect("a registry");
            mvs_protocol::relay_wire::parse_address(&r.address).expect("an address").port
        };
        assert_eq!(port("reg.example"), mvs_protocol::registry_wire::REGISTRY_PORT);
        assert_eq!(port("reg.example:7777"), 7777);
        assert_eq!(port("[::1]"), mvs_protocol::registry_wire::REGISTRY_PORT);
        assert_eq!(port("[::1]:7000"), 7000);
        assert_eq!(port("::1"), mvs_protocol::registry_wire::REGISTRY_PORT);
    }

    #[test]
    fn a_bad_id_is_named() {
        let mut b = whole();
        b["id"] = json!("not-an-id");
        names(b, "registry.id");
        let mut b = whole();
        b.as_object_mut().unwrap().remove("id");
        names(b, "registry.id");
    }

    #[test]
    fn a_bad_address_is_named() {
        let mut b = whole();
        b["address"] = json!("reg example");
        names(b, "registry.address");
        let mut b = whole();
        b["public"] = json!(7);
        names(b, "registry.public");
    }

    #[test]
    fn an_unknown_field_is_named() {
        let mut b = whole();
        b["adress"] = json!("reg.example");
        names(b, "registry.adress");
        names(json!("reg.example"), "registry");
    }

    #[test]
    fn a_negative_after_ms_is_named() {
        let mut b = whole();
        b["afterMs"] = json!(-1);
        names(b, "registry.afterMs");
        let mut b = whole();
        b["afterMs"] = json!("soon");
        names(b, "registry.afterMs");
    }
}

#[cfg(test)]
mod unknown_fields {
    use super::*;

    #[test]
    fn a_misspelled_block_is_named() {
        assert_eq!(unknown_fields(r#"{"registery": {}}"#), vec!["registery".to_string()]);
        assert_eq!(unknown_fields(r#"{"port": 1, "host": "", "limits": {}, "registry": {}}"#), Vec::<String>::new());
        assert_eq!(unknown_fields(r#"{"zeta": 1, "port": 1, "alpha": 2}"#), vec!["zeta".to_string(), "alpha".into()]);
    }
}
