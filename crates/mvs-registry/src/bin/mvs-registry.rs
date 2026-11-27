//! mvs-registry: the registry relays check in to, on one TCP port. Its config (mvs-registry.json) and key
//! (mvs-registry.key) are beside the executable, or the config is named by --config with the key beside it; both are
//! made on the first run, and a config without its key beside it stops the registry.
//!
//!   mvs-registry [--port <n>] [--host <ip>] [--config <file>] [--version]

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::Poll;
use std::time::{SystemTime, UNIX_EPOCH};

use mvs_protocol::registry_wire::{REGISTRY_PORT, REGISTRY_WIRE_VERSION};
use mvs_protocol::relay_wire::{is_key_id, parse_address};
use mvs_registry::core::{Admission, Approved, Limits, Mode, Origin};
use mvs_registry::rules::{Ban, Bans};
use mvs_registry::server::{Options, start_registry};
use serde_json::{Value, json};

/// The config's fields, in the order the first run writes them.
const FIELDS: [&str; 11] = [
    "port",
    "host",
    "admission",
    "relays",
    "bans",
    "relaysPerAddress",
    "connectsPerMinute",
    "checks",
    "listMs",
    "recheckMs",
    "refreshMs",
];
/// A `relays` entry's fields.
const RELAY_FIELDS: [&str; 3] = ["id", "address", "name"];

/// The config file's settings.
struct Config {
    port: u16,
    /// An IPv4 address to listen on; empty for all of this PC's.
    host: String,
    admission: Admission,
    limits: Limits,
}

/// `YYYY-MM-DD HH:MM:SSZ`, UTC (as the relay's log).
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
    eprintln!("mvs-registry: {why}");
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

/// A port: 0 picks one.
fn port(v: &Value, what: &str) -> u16 {
    let n = match v {
        Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => s.parse::<f64>().ok(),
        Value::Number(n) => n.as_f64(),
        _ => None,
    };
    match n {
        Some(n) if n.fract() == 0.0 && (0.0..=65535.0).contains(&n) => n as u16,
        _ => fail(&format!("{what} is not a port (0 to 65535; 0 picks one)")),
    }
}

/// An address to listen on: an IPv4 one, or empty for all.
fn host(h: &str, what: &str) -> String {
    if !h.is_empty() && h.parse::<Ipv4Addr>().is_err() {
        fail(&format!("{what} is not an IPv4 address (the registry listens on IPv4 only)"));
    }
    h.to_string()
}

/// A number above 0.
fn positive(v: &Value, what: &str) -> f64 {
    match v.as_f64() {
        Some(n) if n.is_finite() && n > 0.0 => n,
        _ => fail(&format!("{what} is not a number above 0")),
    }
}

/// A whole number of 1 or more.
fn count(v: &Value, what: &str) -> u32 {
    match v.as_f64() {
        Some(n) if n.fract() == 0.0 && (1.0..=f64::from(u32::MAX)).contains(&n) => n as u32,
        _ => fail(&format!("{what} is not a whole number of 1 or more")),
    }
}

/// A limit as JSON writes it: a whole number without its point.
fn number(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 9007199254740992.0 { json!(v as i64) } else { json!(v) }
}

/// The defaults, in the order of [`FIELDS`], two spaces to a level.
fn defaults_text() -> String {
    let l = Limits::default();
    let lines = [
        format!("\"port\": {REGISTRY_PORT}"),
        "\"host\": \"\"".to_string(),
        "\"admission\": \"open\"".to_string(),
        "\"relays\": []".to_string(),
        "\"bans\": []".to_string(),
        format!("\"relaysPerAddress\": {}", l.per_address),
        format!("\"connectsPerMinute\": {}", number(l.connects_per_minute)),
        format!("\"checks\": {}", l.checks),
        format!("\"listMs\": {}", number(l.list_ms)),
        format!("\"recheckMs\": {}", number(l.recheck_ms)),
        format!("\"refreshMs\": {}", number(l.refresh_ms)),
    ];
    format!("{{\n  {}\n}}\n", lines.join(",\n  "))
}

/// A `relays` entry: an approved relay from the config.
fn relay(v: &Value, what: &str) -> Approved {
    let Value::Object(e) = v else { fail(&format!("{what} is not an object")) };
    for k in e.keys() {
        if !RELAY_FIELDS.contains(&k.as_str()) {
            fail(&format!("{what}.{k} is not a field ({})", RELAY_FIELDS.join(", ")));
        }
    }
    let id = match e.get("id") {
        Some(Value::String(id)) if is_key_id(id) => id.clone(),
        _ => fail(&format!("{what}.id is not a relay id (r and 32 hex digits)")),
    };
    let text = |k: &str| match e.get(k) {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => fail(&format!("{what}.{k} is not text")),
    };
    let address = text("address");
    if address.as_deref().is_some_and(|a| parse_address(a).is_none()) {
        fail(&format!("{what}.address is not an address (host:port)"));
    }
    Approved { id, address, name: text("name"), origin: Origin::Config }
}

/// The config file's, over the defaults; written with the defaults when there is none.
fn read_config(file: &Path) -> Config {
    let f = file.display();
    let mut out = Config {
        port: REGISTRY_PORT,
        host: String::new(),
        admission: Admission { mode: Mode::Open, approved: Vec::new(), bans: Bans::new(Vec::new()) },
        limits: Limits::default(),
    };
    if !file.exists() {
        if let Err(e) = std::fs::write(file, defaults_text()) {
            fail(&format!("could not write {f}: {e}"));
        }
        say(&format!("wrote {f} with the defaults"));
        return out;
    }
    let text = std::fs::read_to_string(file).unwrap_or_else(|e| fail(&format!("could not read {f}: {e}")));
    let raw: Value = serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .unwrap_or_else(|e| fail(&format!("{f} is not JSON: {e}")));
    let Value::Object(c) = raw else { fail(&format!("{f} is not a JSON object")) };
    for k in c.keys() {
        if !FIELDS.contains(&k.as_str()) {
            fail(&format!("{f}: {k} is not a setting ({})", FIELDS.join(", ")));
        }
    }
    let get = |k: &str| c.get(k);
    if let Some(p) = get("port") {
        out.port = port(p, &format!("{f}: port"));
    }
    if let Some(h) = get("host") {
        let Value::String(h) = h else { fail(&format!("{f}: host is not text")) };
        out.host = host(h, &format!("{f}: host"));
    }
    if let Some(a) = get("admission") {
        out.admission.mode = match a.as_str() {
            Some("open") => Mode::Open,
            Some("list") => Mode::List,
            _ => fail(&format!("{f}: admission is not \"open\" or \"list\"")),
        };
    }
    if let Some(r) = get("relays") {
        let Value::Array(r) = r else { fail(&format!("{f}: relays is not a list")) };
        let mut ids = HashSet::new();
        for (i, v) in r.iter().enumerate() {
            let what = format!("{f}: relays[{i}]");
            let a = relay(v, &what);
            if !ids.insert(a.id.clone()) {
                fail(&format!("{what}.id is there twice"));
            }
            out.admission.approved.push(a);
        }
    }
    if let Some(b) = get("bans") {
        let Value::Array(b) = b else { fail(&format!("{f}: bans is not a list")) };
        let mut bans = Vec::new();
        for (i, v) in b.iter().enumerate() {
            let Value::String(t) = v else { fail(&format!("{f}: bans[{i}] is not text")) };
            match Ban::parse(t) {
                Ok(ban) => bans.push(ban),
                Err(e) => fail(&format!("{f}: bans[{i}]: {e}")),
            }
        }
        out.admission.bans = Bans::new(bans);
    }
    let l = &mut out.limits;
    for k in &FIELDS[5..] {
        let Some(v) = get(k) else { continue };
        let what = format!("{f}: {k}");
        match *k {
            "relaysPerAddress" => l.per_address = count(v, &what),
            "connectsPerMinute" => l.connects_per_minute = positive(v, &what),
            "checks" => l.checks = count(v, &what),
            "listMs" => l.list_ms = positive(v, &what),
            "recheckMs" => l.recheck_ms = positive(v, &what),
            _ => l.refresh_ms = positive(v, &what),
        }
    }
    if out.admission.mode == Mode::List && out.admission.approved.is_empty() {
        fail(&format!("{f}: admission is \"list\" and relays is empty: no relay could check in"));
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
        println!("mvs-registry {version} (registry wire {REGISTRY_WIRE_VERSION})");
        return;
    }
    let here = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_default();
    let config_file = match arg(&args, "--config") {
        Some(c) => std::path::absolute(&c).unwrap_or_else(|_| PathBuf::from(c)),
        None => here.join("mvs-registry.json"),
    };
    let key_file =
        config_file.parent().map(|d| d.join("mvs-registry.key")).unwrap_or_else(|| "mvs-registry.key".into());
    if config_file.exists() && !key_file.exists() {
        fail(&format!(
            "{} is there but its key {} is not: restore the key from backup (a new key is a new registry id, which the relays pinned to this registry refuse); delete the config to start as a new registry",
            config_file.display(),
            key_file.display()
        ));
    }
    // (the key first: a first run that fails after it never leaves a config without its key)
    if let Err(e) = mvs_relay::server::load_key(Some(&key_file)) {
        fail(&format!("could not make or read the key {}: {e}", key_file.display()));
    }
    let mut config = read_config(&config_file);
    if let Some(p) = arg(&args, "--port") {
        config.port = port(&Value::String(p), "--port");
    }
    if let Some(h) = arg(&args, "--host") {
        config.host = host(&h, "--host");
    }
    let mode = match config.admission.mode {
        Mode::Open => "open",
        Mode::List => "list",
    };
    let (relays, bans) = (config.admission.approved.len(), config.admission.bans.list().len());

    // Every connection's handling is guarded in the server (a panic there closes that connection). A panic is logged
    // by where it was, never by its message, which may hold a relay's text.
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
            admission: config.admission,
            limits: config.limits,
            log: Some(Box::new(say)),
            ..Options::default()
        };
        let registry = match start_registry(o) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                fail(&format!("port {} is in use by another program (--port picks another)", config.port))
            }
            Err(e) => fail(&format!("could not listen on port {}: {e}", config.port)),
        };
        say(&format!(
            "mvs-registry {version} (registry wire {REGISTRY_WIRE_VERSION}), registry id {}, port {} (TCP), admission {mode}, {relays} relays and {bans} bans in its config",
            registry.id, registry.port
        ));
        say(&format!("config {}", config_file.display()));
        say("relays connect to this PC's outside address and that port; behind a router, forward it (TCP) to this PC. Ctrl+C stops");
        let first = stop_signal().await;
        say(&format!("{first}: stopping"));
        let mut closing = pin!(registry.close());
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
