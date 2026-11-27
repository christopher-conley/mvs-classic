//! The registry's two web pages, each on its own port: the public one, where a relay's address is submitted and the
//! approved relays checked in now are listed, and the admin one (approve, remove, ban, unban) behind a token.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Form, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mvs_protocol::relay_wire::parse_address;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::core::{Approved, Origin, Seen};
use crate::rules::{Ban, NO_IPV6};
use crate::state::{SUBMIT_RATE, SubmitCx, Submitted, Waiting, submit};

/// The most bytes a request's body may hold, on either page.
pub const BODY_LIMIT: usize = 4096;
/// The page's answer to a change it cannot make to an entry of the config.
pub const CONFIG_ENTRY: &str = "edit the config to remove this one";
pub const NOT_WAITING: &str = "that relay is not waiting";
pub const NOT_APPROVED: &str = "that relay is not approved";
pub const NOT_BANNED: &str = "that ban is not there";
/// A change the registry made but could not save (the log line says why).
pub const NOT_SAVED: &str = "the change is made, but the state file could not be written (the registry's log says why)";
/// An admin post without the page's hidden `form` field: another site's form posting through the admin's browser.
pub const NOT_THE_FORM: &str = "that form is not the admin page's";
/// The pages' requests the registry has not taken yet; past them a page waits.
const QUEUE: usize = 64;

/// Where the two pages listen (IPv4 addresses, "" for all of this PC's), and the token the admin page asks for
/// ("" leaves the admin page off).
pub struct PageOptions {
    pub port: u16,
    pub host: String,
    pub admin_port: u16,
    pub admin_host: String,
    pub admin_token: String,
}

/// The pages running; dropped, both stop listening.
pub struct Pages {
    /// The ports they listen on; the admin page's None when it is off.
    pub port: u16,
    pub admin_port: Option<u16>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Pages {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// A page's port that would not listen: the config's field that names it, the port, and why.
#[derive(Debug)]
pub struct BindError {
    pub what: &'static str,
    pub port: u16,
    pub error: io::Error,
}

/// A relay on the public page: approved and checked in now.
struct Listed {
    id: String,
    address: String,
    name: Option<String>,
}

/// What the admin page lists. A ban is the page's when the state file holds it.
struct AdminView {
    seen: Vec<Seen>,
    approved: Vec<Approved>,
    waiting: Vec<Waiting>,
    bans: Vec<(Ban, bool)>,
}

/// A change from the admin page.
enum Change {
    /// A waiting relay approved, as the page's.
    Approve(String),
    /// A page approval removed.
    Remove(String),
    Ban(Ban),
    /// A page ban lifted.
    Unban(Ban),
}

/// A page's request of the registry, with where its answer goes. The pages are served by `Send` tasks; the registry
/// is not `Send`, so they reach it only through these, answered on its own thread.
enum Ask {
    Listed(oneshot::Sender<Vec<Listed>>),
    Submit {
        source: Ipv4Addr,
        address: String,
        name: Option<String>,
        answer: oneshot::Sender<Result<Submitted, &'static str>>,
    },
    Admin(oneshot::Sender<AdminView>),
    Change(Change, oneshot::Sender<Result<(), &'static str>>),
}

/// What a page's handlers share: the way to the registry, and the admin page's token.
#[derive(Clone)]
struct Page {
    asks: mpsc::Sender<Ask>,
    token: Arc<str>,
}

impl Page {
    /// The registry's answer; None when it no longer answers.
    async fn ask<T>(&self, make: impl FnOnce(oneshot::Sender<T>) -> Ask) -> Option<T> {
        let (tx, rx) = oneshot::channel();
        self.asks.send(make(tx)).await.ok()?;
        rx.await.ok()
    }
}

/// Both pages listening, and the task that answers them on the registry's thread. Called inside the registry's
/// `LocalSet`. The start lines go to the registry's log; nothing a page is sent ever does.
pub fn start_pages(o: PageOptions, cx: SubmitCx) -> Result<Pages, BindError> {
    let public = bind(&o.host, o.port).map_err(|error| BindError { what: "web.port", port: o.port, error })?;
    let admin = if o.admin_token.is_empty() {
        None
    } else {
        let what = "web.adminPort";
        Some(bind(&o.admin_host, o.admin_port).map_err(|error| BindError { what, port: o.admin_port, error })?)
    };
    let (asks, rx) = mpsc::channel(QUEUE);
    let page = Page { asks, token: o.admin_token.as_str().into() };
    let mut tasks = Vec::new();
    let port = public.1;
    tasks.push(serve(public.0, public_router(page.clone())));
    cx.registry.log(&format!("public page on {}", place(&o.host, port)));
    let admin_port = match admin {
        Some((listener, port)) => {
            tasks.push(serve(listener, admin_router(page)));
            cx.registry.log(&format!("admin page on {}", place(&o.admin_host, port)));
            Some(port)
        }
        None => {
            cx.registry.log("admin page off (no adminToken)");
            None
        }
    };
    let registry = cx.registry.clone();
    tasks.push(registry.spawn(answer(Rc::new(cx), rx)));
    Ok(Pages { port, admin_port, tasks })
}

/// A listening socket on `host` ("" for all) and `port` (0 picks one), and the port it got.
fn bind(host: &str, port: u16) -> io::Result<(TcpListener, u16)> {
    let ip: Ipv4Addr = if host.is_empty() {
        Ipv4Addr::UNSPECIFIED
    } else {
        host.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an IPv4 address"))?
    };
    let l = std::net::TcpListener::bind(SocketAddrV4::new(ip, port))?;
    l.set_nonblocking(true)?;
    let l = TcpListener::from_std(l)?;
    let port = l.local_addr()?.port();
    Ok((l, port))
}

/// `port N` for all addresses, else `host:N`.
fn place(host: &str, port: u16) -> String {
    if host.is_empty() { format!("port {port}") } else { format!("{host}:{port}") }
}

/// One page served on its own (`Send`) task, each request given its source address.
fn serve(listener: TcpListener, router: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
    })
}

/// The registry's side: each request answered with what it holds now. A submission runs on a task of its own, so a
/// check (up to `prove_ms`) holds no other page.
async fn answer(cx: Rc<SubmitCx>, mut rx: mpsc::Receiver<Ask>) {
    while let Some(ask) = rx.recv().await {
        match ask {
            Ask::Listed(tx) => {
                let _ = tx.send(listed(&cx));
            }
            Ask::Submit { source, address, name, answer } => {
                let cx = cx.clone();
                let registry = cx.registry.clone();
                registry.spawn(async move {
                    let now = cx.registry.with_core(|_, now| now);
                    let _ = answer.send(submit(&cx, source, &address, name.as_deref(), now).await);
                });
            }
            Ask::Admin(tx) => {
                let _ = tx.send(admin_view(&cx));
            }
            Ask::Change(c, tx) => {
                let _ = tx.send(change(&cx, c));
            }
        }
    }
}

fn listed(cx: &SubmitCx) -> Vec<Listed> {
    cx.registry.with_core(|r, _| {
        let approved = r.approved();
        r.seen()
            .into_iter()
            .filter(|s| s.listed && s.approved)
            .filter_map(|s| {
                let id = s.id?;
                let name = approved.iter().find(|a| a.id == id).and_then(|a| a.name.clone());
                Some(Listed { address: s.address.unwrap_or_default(), id, name })
            })
            .collect()
    })
}

fn admin_view(cx: &SubmitCx) -> AdminView {
    let (seen, approved, bans) = cx.registry.with_core(|r, _| (r.seen(), r.approved().to_vec(), r.bans().to_vec()));
    let st = cx.state.borrow();
    let bans = bans.into_iter().map(|b| (b.clone(), st.bans.contains(&b))).collect();
    AdminView { seen, approved, waiting: st.waiting.clone(), bans }
}

/// A change applied to the registry and the state, then saved. A config entry is refused (CONFIG_ENTRY).
fn change(cx: &SubmitCx, c: Change) -> Result<(), &'static str> {
    let mut st = cx.state.borrow_mut();
    let origin = |id: &str| cx.registry.with_core(|r, _| r.approved().iter().find(|e| e.id == id).map(|e| e.origin));
    match c {
        Change::Approve(id) => {
            let i = st.waiting.iter().position(|w| w.id == id).ok_or(NOT_WAITING)?;
            let w = st.waiting.remove(i);
            // (an id the config approved meanwhile stays the config's)
            if origin(&id) != Some(Origin::Config) {
                let a = Approved { id: w.id, address: Some(w.address), name: w.name, origin: Origin::Page };
                match st.approved.iter_mut().find(|e| e.id == id) {
                    Some(e) => *e = a.clone(),
                    None => st.approved.push(a.clone()),
                }
                cx.registry.with_core(|r, now| r.approve(a, now));
            }
        }
        Change::Remove(id) => match origin(&id) {
            None => return Err(NOT_APPROVED),
            Some(Origin::Config) => return Err(CONFIG_ENTRY),
            Some(Origin::Page) => {
                cx.registry.with_core(|r, now| r.unapprove(&id, now));
                st.approved.retain(|e| e.id != id);
            }
        },
        Change::Ban(b) => {
            if cx.registry.with_core(|r, now| r.ban(b.clone(), now)) {
                st.bans.push(b);
            }
        }
        Change::Unban(b) => match st.bans.iter().position(|x| *x == b) {
            Some(i) => {
                st.bans.remove(i);
                cx.registry.with_core(|r, _| r.unban(&b));
            }
            None if cx.registry.with_core(|r, _| r.bans().contains(&b)) => return Err(CONFIG_ENTRY),
            None => return Err(NOT_BANNED),
        },
    }
    if let Err(e) = st.save(&cx.path) {
        cx.registry.log(&format!("state: could not save: {e}"));
        return Err(NOT_SAVED);
    }
    Ok(())
}

/// HTML's escape of a text: every value a page writes goes through it.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A whole page: its title (escaped here) and its body (HTML already).
fn html(status: StatusCode, title: &str, body: &str) -> Response {
    let t = esc(title);
    let text = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width\">\n<title>{t}</title>\n</head>\n\
         <body>\n<h1>{t}</h1>\n{body}</body>\n</html>\n"
    );
    (status, Html(text)).into_response()
}

/// A page of one text (escaped), with the way back.
fn note(status: StatusCode, title: &str, text: &str) -> Response {
    html(status, title, &format!("<p>{}</p>\n<p><a href=\"/\">Back</a></p>\n", esc(text)))
}

/// A request whose registry side is gone: the `Pages` were dropped (their answering task with them) while a
/// connection a page had taken still runs. A panic there never gets here: it ends the program.
fn not_answering() -> Response {
    note(StatusCode::SERVICE_UNAVAILABLE, "mvs-registry", "the registry is not answering")
}

/// A table of rows of cells (HTML already) under escaped headings.
fn table(heads: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "<p>None.</p>\n".into();
    }
    let mut out = String::from("<table>\n<tr>");
    for h in heads {
        out += &format!("<th>{}</th>", esc(h));
    }
    out += "</tr>\n";
    for r in rows {
        out += "<tr>";
        for c in r {
            out += &format!("<td>{c}</td>");
        }
        out += "</tr>\n";
    }
    out + "</table>\n"
}

fn yes(b: bool) -> String {
    (if b { "yes" } else { "no" }).into()
}

fn public_router(page: Page) -> Router {
    Router::new()
        .route("/", get(public_page))
        .route("/submit", post(submitted))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(page)
}

async fn public_page(State(page): State<Page>) -> Response {
    let Some(listed) = page.ask(Ask::Listed).await else { return not_answering() };
    let rows: Vec<Vec<String>> =
        listed.iter().map(|l| vec![esc(l.name.as_deref().unwrap_or_default()), esc(&l.address), esc(&l.id)]).collect();
    let body = format!(
        "<form method=\"post\" action=\"/submit\">\n\
         <p><label>A relay's address (host:port) <input name=\"address\" required></label></p>\n\
         <p><label>Its name (optional) <input name=\"name\" maxlength=\"40\"></label></p>\n\
         <p><button>Submit</button></p>\n</form>\n<h2>Approved relays checked in now</h2>\n{}",
        table(&["Name", "Address", "Id"], &rows)
    );
    html(StatusCode::OK, "mvs-registry relays", &body)
}

/// A submission from `from`: what came of it, in the reason's text, with the address read back. The name is never
/// shown back.
async fn submitted(
    State(page): State<Page>,
    ConnectInfo(from): ConnectInfo<SocketAddr>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let address = f.get("address").cloned().unwrap_or_default();
    let got = match from {
        SocketAddr::V4(from) => {
            let name = f.get("name").cloned();
            let asked = page.ask(|answer| Ask::Submit { source: *from.ip(), address: address.clone(), name, answer });
            let Some(got) = asked.await else { return not_answering() };
            got
        }
        SocketAddr::V6(_) => Err(NO_IPV6),
    };
    let (status, text) = match got {
        Ok(Submitted::Approved(id)) => (StatusCode::OK, format!("{address}: the relay {id} is approved.")),
        Ok(Submitted::Waiting(id)) => {
            (StatusCode::OK, format!("{address}: the relay {id} is waiting for the registry's owner."))
        }
        Err(why) if why == SUBMIT_RATE => (StatusCode::TOO_MANY_REQUESTS, format!("{address}: {why}")),
        Err(why) => (StatusCode::BAD_REQUEST, format!("{address}: {why}")),
    };
    note(status, "Submission", &text)
}

fn admin_router(page: Page) -> Router {
    Router::new()
        .route("/", get(admin_page))
        .route("/approve", post(approve))
        .route("/remove", post(remove))
        .route("/ban", post(ban))
        .route("/unban", post(unban))
        .layer(from_fn_with_state(page.clone(), authorized))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(page)
}

/// Every admin request needs HTTP Basic authorization whose password is the token (any user name): else 401, for
/// the browser to ask for it.
async fn authorized(State(page): State<Page>, req: Request, next: Next) -> Response {
    let password = req.headers().get(header::AUTHORIZATION).and_then(|v| basic_password(v.as_bytes()));
    if password.is_some_and(|p| same(&p, page.token.as_bytes())) {
        return next.run(req).await;
    }
    let mut r = note(StatusCode::UNAUTHORIZED, "mvs-registry admin", "this page needs the registry's adminToken");
    r.headers_mut().insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static("Basic realm=\"mvs-registry\""));
    r
}

/// The password of an `Authorization: Basic` value: what follows the first `:` of its base64.
fn basic_password(v: &[u8]) -> Option<Vec<u8>> {
    let v = std::str::from_utf8(v).ok()?;
    let (scheme, rest) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = STANDARD.decode(rest.trim()).ok()?;
    let at = raw.iter().position(|&b| b == b':')?;
    Some(raw[at + 1..].to_vec())
}

/// Equal bytes, compared in a time that does not tell how much of them matched (unequal lengths are unequal).
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    std::hint::black_box(d) == 0
}

/// A form of the admin page's own: carries its hidden `form` field, the token.
fn the_form(page: &Page, f: &HashMap<String, String>) -> bool {
    f.get("form").is_some_and(|v| same(v.as_bytes(), page.token.as_bytes()))
}

/// A button that posts `value` as `field` to `path`, with the page's hidden field.
fn button(page: &Page, path: &str, field: &str, value: &str, label: &str) -> String {
    format!(
        "<form method=\"post\" action=\"{path}\"><input type=\"hidden\" name=\"form\" value=\"{}\">\
         <input type=\"hidden\" name=\"{field}\" value=\"{}\"><button>{}</button></form>",
        esc(&page.token),
        esc(value),
        esc(label)
    )
}

/// The buttons that ban an id and an IP, each where there is one.
fn ban_buttons(page: &Page, id: Option<&str>, ip: Option<Ipv4Addr>) -> String {
    let mut out = String::new();
    if let Some(id) = id {
        out += &button(page, "/ban", "ban", id, "Ban its id");
    }
    if let Some(ip) = ip {
        out += &button(page, "/ban", "ban", &ip.to_string(), "Ban its IP");
    }
    out
}

fn origin(o: Origin) -> String {
    (match o {
        Origin::Config => "from config",
        Origin::Page => "from the page",
    })
    .into()
}

async fn admin_page(State(page): State<Page>) -> Response {
    let Some(v) = page.ask(Ask::Admin).await else { return not_answering() };
    let opt = |s: &Option<String>| esc(s.as_deref().unwrap_or_default());
    let seen: Vec<Vec<String>> = v
        .seen
        .iter()
        .map(|s| {
            let who = s.id.clone().unwrap_or_else(|| s.source.to_string());
            vec![
                esc(&who),
                esc(&s.source.to_string()),
                opt(&s.address),
                yes(s.listed),
                yes(s.approved),
                ban_buttons(&page, s.id.as_deref(), Some(s.source)),
            ]
        })
        .collect();
    let approved: Vec<Vec<String>> = v
        .approved
        .iter()
        .map(|a| {
            let ip = a.address.as_deref().and_then(parse_address).and_then(|p| p.host.parse::<Ipv4Addr>().ok());
            let remove = match a.origin {
                Origin::Page => button(&page, "/remove", "id", &a.id, "Remove"),
                Origin::Config => esc(CONFIG_ENTRY),
            };
            vec![
                esc(&a.id),
                opt(&a.name),
                opt(&a.address),
                origin(a.origin),
                remove + &ban_buttons(&page, Some(&a.id), ip),
            ]
        })
        .collect();
    let waiting: Vec<Vec<String>> = v
        .waiting
        .iter()
        .map(|w| {
            let approve = button(&page, "/approve", "id", &w.id, "Approve");
            vec![esc(&w.id), opt(&w.name), esc(&w.address), w.since.to_string(), approve]
        })
        .collect();
    let bans: Vec<Vec<String>> = v
        .bans
        .iter()
        .map(|(b, from_page)| {
            let text = b.text();
            let (from, lift) = if *from_page {
                (origin(Origin::Page), button(&page, "/unban", "ban", &text, "Unban"))
            } else {
                (origin(Origin::Config), esc(CONFIG_ENTRY))
            };
            vec![esc(&text), from, lift]
        })
        .collect();
    let body = format!(
        "<h2>Connections</h2>\n{}<h2>Approved</h2>\n{}<h2>Waiting</h2>\n{}<h2>Bans</h2>\n{}\
         <form method=\"post\" action=\"/ban\"><input type=\"hidden\" name=\"form\" value=\"{}\">\
         <label>Ban (a relay id, an IPv4 address, a range, a block or a host name) \
         <input name=\"ban\" required></label> \
         <button>Ban</button></form>\n",
        table(&["Relay", "Source IP", "Listed address", "Listed", "Approved", ""], &seen),
        table(&["Id", "Name", "Address", "From", ""], &approved),
        table(&["Id", "Name", "Address", "Since (unix seconds)", ""], &waiting),
        table(&["Ban", "From", ""], &bans),
        esc(&page.token)
    );
    html(StatusCode::OK, "mvs-registry admin", &body)
}

/// A change from an admin form: 403 without the page's own field, else the registry's answer: back to the page
/// (303), or why not.
async fn changed(
    page: &Page,
    f: &HashMap<String, String>,
    c: impl FnOnce(&str) -> Result<Change, String>,
    key: &str,
) -> Response {
    if !the_form(page, f) {
        return note(StatusCode::FORBIDDEN, "mvs-registry admin", NOT_THE_FORM);
    }
    let c = match c(f.get(key).map(String::as_str).unwrap_or_default()) {
        Ok(c) => c,
        Err(why) => return note(StatusCode::BAD_REQUEST, "mvs-registry admin", &why),
    };
    match page.ask(|tx| Ask::Change(c, tx)).await {
        None => not_answering(),
        Some(Ok(())) => Redirect::to("/").into_response(),
        Some(Err(why)) if why == NOT_SAVED => note(StatusCode::INTERNAL_SERVER_ERROR, "mvs-registry admin", why),
        Some(Err(why)) => note(StatusCode::BAD_REQUEST, "mvs-registry admin", why),
    }
}

/// One ban's text read (`Ban::parse`); its error names the text.
fn read_ban(text: &str) -> Result<Ban, String> {
    Ban::parse(text).map_err(|e| format!("{text}: {e}"))
}

async fn approve(State(page): State<Page>, Form(f): Form<HashMap<String, String>>) -> Response {
    changed(&page, &f, |id| Ok(Change::Approve(id.into())), "id").await
}

async fn remove(State(page): State<Page>, Form(f): Form<HashMap<String, String>>) -> Response {
    changed(&page, &f, |id| Ok(Change::Remove(id.into())), "id").await
}

async fn ban(State(page): State<Page>, Form(f): Form<HashMap<String, String>>) -> Response {
    changed(&page, &f, |t| read_ban(t).map(Change::Ban), "ban").await
}

async fn unban(State(page): State<Page>, Form(f): Form<HashMap<String, String>>) -> Response {
    changed(&page, &f, |t| read_ban(t).map(Change::Unban), "ban").await
}
