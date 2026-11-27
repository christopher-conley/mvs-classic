# Running a registry

A registry is where relays check in. A relay whose config names a registry dials it, proves its key, and says at
which address players reach it; the registry dials that address, makes sure the same relay answers there, and lists
it. Each listed relay hears which other relays of its game version are listed, and when one comes or goes. A
registry has two web pages beside it: a public one, where anyone can add a relay's address, and an admin one,
where its owner approves, removes and bans relays.

What the registry's owner should know first:
- A registry carries no match and no lobby, and players' games never connect to it. A relay sends it only the
  address players reach it at and its load (players and matches, each with its limit); the registry keeps the load
  to itself and sees no player's address. A relay serves its players the same whether it is checked in or not.
- A relay that is listed keeps the list it hears, and does nothing else with it.
- The registry is not in a release yet: you build it from the source (below).
- The pages speak plain HTTP. The admin page's token crosses the network in clear unless you reach the page on
  the registry's own PC or through an SSH tunnel (below).

## Download and start

Build it from the source with `cargo build --release -p mvs-registry`: the program is
`target/release/mvs-registry` (`mvs-registry.exe` on Windows). Put it in a folder of its own and start it from a
terminal to see its log.

A fault in one relay's connection closes that connection only. A fault outside them (a bug) logs
`uncaught panic; stopping` and stops the program with exit code 1, so a registry meant to stay up runs under
something that starts it again: a systemd service with `Restart=on-failure`, or a Windows scheduled task.

On its first start it writes two files beside itself:
- `mvs-registry.json`, the config (below), with a new random `adminToken` in it;
- `mvs-registry.key`, the registry's own key. Its id, made from it, is in the start line
  (`registry id r...`): every relay that checks in names that id in its config, and refuses a registry at that
  address that proves another key. Do not share the key.

A third file, `mvs-registry-state.json`, is written beside the config the first time a page changes something:
the approvals and bans made on the admin page, and the submissions waiting for your review. The registry never
writes its config.

A config without its key beside it does not start (`restore the key from backup`): a lost key is put back from
its backup, never made anew without the owner knowing. To start as a new registry on purpose (a new id), delete the
config too.

It prints the port it listens on, where the pages are, and a line for each relay that is listed, refused or
gone. Stop it with Ctrl+C (or `systemctl stop`); it tells every relay `registry stopping` and closes. A second
Ctrl+C stops it at once.

Options: `--port <n>` and `--host <ip>` (this run only), `--config <file>` (another config; the key and the state
file go beside it), `--version`.

The registry reads its config at the start only: restart it after an edit.

### Back up the key, the config and the state file

Copy all three off the PC or server and keep the copies offline:
- `mvs-registry.key`: a registry whose key is lost has a new id, and every relay that names the old one refuses it
  until its owner edits the relay's config.
- `mvs-registry.json`: your admission, your bans, the relays you approved there, and the `adminToken`. Treat the
  token as a password: anyone who has it and reaches the admin page can approve and ban relays.
- `mvs-registry-state.json`: what the pages approved and banned. Without it those approvals and bans are gone, and
  in `list` admission the relays the pages approved can no longer check in.

To change the token, write a new one in `adminToken` and restart. An empty `adminToken` turns the admin page off.

### On a Linux server

A systemd service runs it under a user of its own, started again after a fault and at boot, with the folder
`/opt/mvs-registry` for the program, its config, its key and its state file:

```
sudo useradd --system --home /opt/mvs-registry --shell /usr/sbin/nologin mvs-registry
sudo install -d -o mvs-registry -g mvs-registry /opt/mvs-registry
sudo install -o mvs-registry -g mvs-registry -m 755 mvs-registry /opt/mvs-registry/
sudo install -m 644 mvs-registry.service /etc/systemd/system/ && sudo systemctl enable --now mvs-registry
```

where `mvs-registry.service` is:

```
[Unit]
Description=MVS Classic registry
After=network-online.target
Wants=network-online.target

[Service]
User=mvs-registry
Group=mvs-registry
WorkingDirectory=/opt/mvs-registry
ExecStart=/opt/mvs-registry/mvs-registry --config /opt/mvs-registry/mvs-registry.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/mvs-registry

[Install]
WantedBy=multi-user.target
```

`journalctl -u mvs-registry` shows its log, and `journalctl -u mvs-registry | grep "registry id"` its id. To
update it, install the new `mvs-registry` over the old one and `systemctl restart mvs-registry`; the key stays, so
the registry's id does not change.

## Open the ports

- **7776 (TCP)**, the relays' port. Open it to the internet: in the provider's firewall and the server's own
  (`ufw allow 7776/tcp`), or forward it on a home router to the PC.
- **7775 (TCP)**, the public page. Open it if anyone but you is to add relays.
- **7774 (TCP)**, the admin page. Do not open it. It listens on `127.0.0.1` only, so it is reached from the
  registry's own PC, or from yours through an SSH tunnel:
  `ssh -L 7774:127.0.0.1:7774 you@registry.example.org`, then open `http://127.0.0.1:7774/` in your browser. In a
  container, set `adminHost` to `""` and map the port to the host's localhost only (`-p 127.0.0.1:7774:7774`).

The registry listens on IPv4 only. It also dials out: to each relay's address, to check it (below).

## Give relays the address and the id

A relay joins with a `registry` block in its config: the registry's address (`registry.example.org`, or
`registry.example.org:7776`; the port can be left out when it is 7776), the registry's id from the start line, and
the address players reach that relay at. [relay.md](relay.md), "Joining a registry", has the block.

## Who is listed

`admission` in the config decides who may check in:
- `"open"` (the default): any relay that is not banned and proves its key at its address is listed. The ones you
  approved are marked approved.
- `"list"`: only the relays you approved, in the config's `relays` or on the pages. Another is refused at its
  start (`this relay is not on the registry's list`).

A relay is listed only after the registry dials the address it gave and the relay there proves the same key. A
relay that names an address another relay answers at is refused (`that address did not prove this relay's key`),
and the relay at that address is not disturbed.

The addresses it takes:
- A private address (`10.x`, `172.16.x` to `172.31.x`, `192.168.x`), a carrier-grade NAT one (`100.64.x` to
  `100.127.x`) and a loopback one (`127.x`) are taken only from the config: a relay's entry in `relays` whose
  `address` is the one the relay checks in with (`a private address is taken only from the registry's config`).
  That is how a registry and its relays on one network, or on one PC, list each other. The public page never takes
  one.
- `0.x`, `169.254.x` (link-local), `224.x` and up (multicast and reserved) are never dialed, from anywhere
  (`that address is never dialed`).
- IPv6 addresses are not taken (`IPv6 addresses are not taken`), and neither is a host name with no IPv4 address.

When a check gets no answer (the relay's port is closed, or its name does not resolve), the relay is checked
again after 15 s, the wait doubling each time, and let go after 6 checks or 10 minutes, whichever comes first
(`not checked in in time`). It dials again by itself later.

A relay that checked in with a host name has that name resolved again every minute while it is listed. A new IPv4
address is checked like the first, and becomes the listed address once the relay proves its key there; one that a
ban or the address rules refuse lets the relay go; a lookup or a check that gets no answer keeps the old address
until the next minute.

The rates, each for one source address:
- 4 relays connected at once (`too many relays from that address`). One IPv4 address can run several relays on
  several ports.
- 12 new connections a minute (`too many connections from that address; try again later`).
- 12 submissions a minute on the public page (`too many submissions from your address; try again later`).

And whatever asks: the registry dials one `ip:port` at most 12 times a minute. A check past that counts as one
that got no answer; a submission past it is answered as past the submission rate.

A registry is updated when the relays' build is. It checks a relay's address with its own build's relay wire,
and refuses a relay of another one (`another relay wire version than this registry's`).

## The public page

`http://registry.example.org:7775/` has a form for a relay's address (`host:port`) and an optional name of up to
40 characters, and lists the approved relays that are checked in now (name, address, id).

A submission is checked as a check-in is, from the public page's side: the registry looks the name up, refuses a
private address and a banned name, address or id, dials the address and asks the relay there for its key. Then:
- with `"submissions": "auto"` (the default), the relay is approved at once (`the relay r... is approved.`);
- with `"submissions": "review"`, it waits for you on the admin page
  (`the relay r... is waiting for the registry's owner.`).

The approval holds the relay's id and the `ip:port` it was proved at, and is saved in the state file. A lookup or
a dial that fails, whatever the cause, is answered only after the whole check's time (5 s), with one text
(`no relay answered at that address`), so the page does not tell a closed port from a filtered one. The log never
holds what was submitted.

## The admin page

`http://127.0.0.1:7774/` asks for a user name and a password: any user name, and the `adminToken` as the password
(HTTP Basic). With `curl`: `curl -u admin:<token> http://127.0.0.1:7774/`.

It lists the connections now (each relay's id, source IP, listed address, and whether it is listed and approved),
the approved relays (each `from config` or `from the page`), the submissions waiting, and the bans. Its buttons
approve a waiting relay, remove an approval the pages made, ban a relay's id or IP, and lift a ban the pages made.
What the config holds is shown and cannot be changed there (`edit the config to remove this one`). Each change is
saved in the state file before the page answers.

Each of its forms carries a hidden field that holds the token, so another site cannot post a form to the admin
page through your browser (`that form is not the admin page's`).

## Bans

A ban is one text, in the config's `bans` or in the admin page's Ban box:
- a relay's id (`r` and 32 hex digits);
- an IPv4 address (`203.0.113.5`);
- a range, both ends included (`203.0.113.1-203.0.113.29`);
- a block (`203.0.113.0/27`; `203.0.113.5/27` reads as the same block);
- a host name (`relay.example.org`, case and a trailing dot ignored).

A ban of an id refuses that relay at its start. A ban of an address, a range or a block refuses connections from
there and relays whose address is there. A ban of a host name refuses a relay that checks in with that name, and
a submission of it. A relay held by a new ban is let go at once, told
`this relay is refused by the registry`; it keeps trying, and is refused each time until the ban is lifted.

## The config

`mvs-registry.json`:

| Field | Default | What it is |
|---|---|---|
| `port` | 7776 | the relays' TCP port |
| `host` | `""` | the IPv4 address to listen on: empty for all of the PC's |
| `admission` | `"open"` | `"open"` or `"list"` (above) |
| `relays` | `[]` | the relays you approve: each `{ "id": "r...", "address": "host:port", "name": "..." }`, `id` needed, the others not; `address` is the one private address the registry takes for that relay |
| `bans` | `[]` | the bans, each a text (above) |
| `relaysPerAddress` | 4 | relays connected from one source address at once |
| `connectsPerMinute` | 12 | new connections from one source address a minute |
| `checks` | 6 | address checks of a relay before it is let go |
| `listMs` | 600000 | the longest a relay may take to be listed |
| `recheckMs` | 15000 | the wait after the first check that gets no answer, doubling after each |
| `refreshMs` | 60000 | how often a listed relay's host name is resolved again |
| `dialsPerMinute` | 12 | dials of one `ip:port` a minute |
| `submissions` | `"auto"` | `"auto"` approves a proved submission, `"review"` keeps it waiting for you |
| `submitsPerMinute` | 12 | submissions from one source address a minute |
| `web` | below | the pages; with no `web` block, no page is served |

The `web` block:

| Field | Default | What it is |
|---|---|---|
| `port` | 7775 | the public page's TCP port |
| `host` | `""` | the IPv4 address the public page listens on: empty for all of the PC's |
| `adminPort` | 7774 | the admin page's TCP port |
| `adminHost` | `"127.0.0.1"` | the IPv4 address the admin page listens on |
| `adminToken` | made on the first start | the admin page's password; empty (or left out) turns the admin page off |

A port of 0 picks a free one. The first start writes every field into the file; delete a line to take the default
again. An unknown field, or a value that is not what its field takes, stops the program with the reason.

## What goes wrong

Each of these stops the program at its start with exit code 1, the reason on stderr after `mvs-registry:`.

- **"... is there but its key ... is not: restore the key from backup":** put `mvs-registry.key` back from its
  backup beside the config. Delete the config only to start as a new registry, with a new id.
- **"port 7776 is in use by another program (--port picks another)":** another registry or program has it; stop
  it, or pick another port and give relays that one.
- **"...: web.port 7775 is in use by another program"** (or `web.adminPort`): another program has a page's port;
  change the port in the `web` block.
- **"...: admission is "list" and relays is empty, as is the approved list of ...: no relay could check in":**
  in `list` admission, approve at least one relay in `relays` (or start in `open`).
- **"...: X is not a setting (...)", "...: web.X is not a field (...)", "...: relays[N].X is not a field
  (...)":** a field is misspelled; the reason lists the ones it takes.
- **"...: relays[N].id is not a relay id (r and 32 hex digits)", "...: relays[N].id is there twice",
  "...: bans[N]: ...":** an entry is wrong; the reason names it.
- **"... is not JSON: ...":** the config or the state file has a typo; the reason names the line and column.

And while it runs:

- **No relay gets listed** (the log has `refused r...: not checked in in time`): the registry cannot reach the
  relay at the address it gave. Open the relay's port to the internet, or, for a relay on your own network, write
  its private address in its `relays` entry.
- **"refused r...: that address did not prove this relay's key":** the address the relay gave is another relay's.
- **"refused r...: another relay wire version than this registry's":** the relay and the registry are of
  different builds; update the older one.
- **"refused r...: this relay is not on the registry's list":** in `list` admission, approve the relay (in
  `relays`, or let it be submitted on the public page); it gets in on its next try.
- **A submission answers "no relay answered at that address":** the address is not reachable from the registry,
  or no relay of this build answers there.
- **An admin change answers "the change is made, but the state file could not be written":** the registry cannot
  write beside its config; the log says why. The change holds until the registry stops.
