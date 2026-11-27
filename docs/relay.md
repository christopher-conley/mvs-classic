# Running a relay

A relay lets players play online without Epic: they type its address in the launcher (Settings > Online, the Relay box; Epic, and LAN when it is on, keep working beside it)
and then find each other's lobbies, invite each other and queue among the players of that relay. It runs no game
rules and keeps no game files; it finds lobbies and passes messages and packets on. Anyone can run one, on a PC at
home or on a rented server, with one port open.

What the relay's owner should know first:
- Traffic between a player and the relay is encrypted after the connection's start, each connection with keys of its
  own: lobby messages, invites, the online list and a match's inputs. The relay opens it to pass it on, so whoever
  runs the relay can read what passes; others on the path cannot read it or change it unseen. What stays in clear:
  the start (the player's key and so their relay id, the app's version, the relay's key), and each UDP packet's
  connection token, counter and length.
- The relay proves its key at the start. That keeps someone on the path out only when the player's game already
  knows the relay's id: the release's own relay (its id is in the release), or a relay the player trusted before (the
  game remembers its id and refuses the address when another key answers). The first time a player connects to
  another relay, someone on the path could answer in its place with a key of their own.
- The relay sees the address of everyone who connects to it. Players never see each other's addresses.
- The relay keeps what each player's game publishes for the online list (the main menu's "+"): their name, icon and
  whether they are in a match, and whether they want to be listed and invited. It lists those who want to be listed
  to every other player of the relay, by name and relay id (never an address), and forgets it when they disconnect.
  A player who takes no invites is answered, to anyone who invites them, as a player who is not online.
- A player on a relay is known by a key their launcher made. Someone can make a new key and so come back as a new
  player: a relay cannot ban a person, only a key or an address (by a firewall).

## Download and start

The release has a zip of the relay beside the game's: `mvs-relay.exe` for Windows and `mvs-relay` for Linux (x64).
Put the program in a folder of its own and start it:

- Windows: double-click `mvs-relay.exe`, or run it from a terminal to see its log.
- Linux: `chmod +x mvs-relay` and `./mvs-relay`.
- From the source: `powershell -File tools/relay-linux.ps1` builds the Linux program on Windows (one static file,
  musl, linked by Rust's own rust-lld: nothing else to install on the server); `cargo build --release -p mvs-relay`
  builds it for the PC it runs on.

A fault in one player's connection closes that connection only. A fault outside them (a bug) logs
`uncaught exception` and stops the program with exit code 1, so a relay meant to stay up runs under something that
starts it again: a systemd service with `Restart=on-failure`, or a Windows scheduled task.

On its first start it writes two files beside itself:
- `mvs-relay.json`, the config (below);
- `mvs-relay.key`, the relay's own key. Keep it: the launcher shows the relay's id, made from it, and players' games
  remember that id and refuse the address when another key answers there. Do not share it.

A config without its key beside it does not start (`restore the key from backup`): a lost key is put back from its
backup, never made anew without the owner knowing. To start as a new relay on purpose (a new id), delete the config
too.

### Back up the relay's key

Copy `mvs-relay.key` off the PC or server (on the Linux server below, `/opt/mvs-relay/mvs-relay.key`, for example
`scp` it home) and keep the copy offline. A relay whose key is lost has a new id when it starts again: every player
who knew it is asked again, and a release that names the relay's id refuses the relay until a new release names the
new one. The id is in the relay's start line: `journalctl -u mvs-relay | grep "relay id"` on the server (in the window
or terminal on a PC).

It prints the addresses it listens on and a line for each player that comes and goes. Stop it with Ctrl+C (or
`systemctl stop`); it tells everyone connected and closes.

Options: `--port <n>` (this run only), `--config <file>` (another config; the key goes beside it), `--version`.

### On a Linux server

A systemd service runs it under a user of its own, started again after a fault and at boot, with the folder
`/opt/mvs-relay` for the program, its config and its key:

```
sudo useradd --system --home /opt/mvs-relay --shell /usr/sbin/nologin mvs-relay
sudo install -d -o mvs-relay -g mvs-relay /opt/mvs-relay
sudo install -o mvs-relay -g mvs-relay -m 755 mvs-relay /opt/mvs-relay/
sudo install -m 644 mvs-relay.service /etc/systemd/system/ && sudo systemctl enable --now mvs-relay
```

where `mvs-relay.service` is:

```
[Unit]
Description=MVS Classic relay
After=network-online.target
Wants=network-online.target

[Service]
User=mvs-relay
Group=mvs-relay
WorkingDirectory=/opt/mvs-relay
ExecStart=/opt/mvs-relay/mvs-relay --config /opt/mvs-relay/mvs-relay.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/mvs-relay

[Install]
WantedBy=multi-user.target
```

`journalctl -u mvs-relay` shows its log. To update it, install the new `mvs-relay` over the old one and
`systemctl restart mvs-relay`; the key stays, so the relay's id does not change (a key the earlier Node relay wrote
reads as well). The release's own relay (`mvsclassic.online`) runs this way. To check a deployed relay from a PC:
`MVS_RELAY_AT=<host>:7777 cargo test -p mvs-net --test relay_queue -- --test-threads=1` (one at a time: a relay takes
4 connections from one address).

## Open the port

Players reach the relay on one port, default 7777, for both TCP and UDP.

- **On a home PC behind a router:** forward the port on the router to this PC, TCP and UDP (the router's page:
  "port forwarding", "virtual server" or "NAT"); the relay does not touch the router itself. Allow the program
  through the PC's firewall too (Windows asks on the first start: allow it on private and public networks if players
  come from the internet).
- **On a rented server:** open the port in the provider's firewall (security group) and the server's own
  (`ufw allow 7777/tcp`, `ufw allow 7777/udp`).
- UDP is used for a match's packets. When it does not get through, matches still work over TCP, with more lag when
  packets are lost.

## Give players the address

Players type `host:port` in the launcher: a name (`relay.example.org:7777`) or an address (`203.0.113.5:7777`,
an IPv6 one in brackets: `[2001:db8::5]:7777`). The port can be left out when it is 7777.

The outside address of a home PC is the router's, not one of the addresses the relay prints (those are the PC's
on its own network, which work for players on the same network). A search for "what is my IP" from the PC shows
it. A home address can change; a free dynamic DNS name keeps one name pointing at it.

Everyone on one relay plays together; players on Epic or on another relay are not seen.

## Joining a registry

A registry is where relays check in ([registry.md](registry.md)). A relay joins one with a `registry` block in
its config. There is none by default, and a relay without one opens no connection for it and logs nothing of it.

```
"registry": {
  "address": "registry.example.org",
  "id": "r00112233445566778899aabbccddeeff",
  "public": "relay.example.org:7777"
}
```

| Field | Default | What it is |
|---|---|---|
| `address` | | the registry's `host:port`; the port is 7776 when none is given |
| `id` | | the registry's id, from its start line; a registry at that address that proves another key is refused |
| `public` | | the address players reach this relay at (`host:port`, the port 7777 when none is given) |
| `afterMs` | 20000 | a number of 0 or more; this release reads it and does nothing with it |

The registry dials `public` to make sure this relay answers there, so the registry must reach the relay at that
address too (for a relay on the registry's own network, the registry's owner writes the private address in the
registry's config). A mistake in the block (a field not known, an id or an address that is not one) stops the relay
at its start with the reason.

The relay's log has two lines for it:
- `registry: checked in`, when the link to the registry has started. The registry then checks the address; the
  registry's log says when the relay is listed.
- `registry: lost: <why>; trying again`, when the link ends: the registry's refusal
  (`this relay is refused by the registry`, for example), or the relay's own reason (`could not connect`, `the
  registry went quiet`, `the registry at that address proved another key`). It is logged once, not for each try:
  the relay dials again by itself, after 2 s and then a wait that doubles up to a minute.

The relay serves its players all along, whether the registry is there or not.

## Playing on one network

Players in one home or at one LAN party need no relay at all. LAN is off until a player turns it on (Settings > Online > LAN, with its
port box) and a custom lobby is hosted on it when neither Epic nor a relay is signed in; the app itself then serves that lobby, on port 7777 (or the next free one;
the port box changes it). The lobby's code starts with `d` and holds the host PC's address on its network, the port
and a check of the host's key. A Public lobby (its Privacy setting) is announced on the network
(UDP port 39417) and shows in the others' Custom Games list, marked LAN, when their LAN is on: a click joins it. A
private one, or a player whose LAN is off, pastes the code in Join Lobby, whatever their Settings > Online say:
their game connects straight to the host and makes sure it is the PC the code names before it joins.

- Nothing on the router is touched, and players outside the network cannot reach the lobby: the host takes
  connections from local network addresses only, and a code can only name such an address (so a code someone sends
  you never makes your game connect to the internet).
- The announcement answers nobody and names no address but the host's own: a PC that hears it sends nothing back.
  The LAN port may be anything but 39417.
- The first time a PC hosts or opens the Custom Games list, Windows may ask whether the app may use the network: allow it on private networks.
  Without that, nobody else can reach the lobby.
- The launcher's Direct line says what the host listens on, or why it cannot (no network, every port taken).
- There is no queue in Direct; Epic's or a relay's queue needs that choice.
- As with a relay, the traffic is encrypted after the start (the host's PC reads it), and the code names the host's
  key: another PC on that network cannot read a match's inputs or the lobby's messages, nor answer in the host's
  place.
- A code is good for one lobby: a new lobby has a new code. A code someone mistyped is refused as mistyped.
- When the host's address changes (another Wi-Fi), an old code no longer reaches it; open a new lobby.

## The config

`mvs-relay.json`:

| Field | Default | What it is |
|---|---|---|
| `port` | 7777 | the TCP and UDP port |
| `host` | `""` | the address to listen on: empty for all of the PC's addresses, IPv4 and IPv6 |
| `limits` | below | what one relay allows |
| `registry` | none | the registry it checks in to ("Joining a registry", above) |

The limits (a player who passes a count or a byte rate is told why and disconnected, the log naming the address; a
search, a join, an invite, an online list ask or a change of a player's entry over its rate, or a lobby past a count,
is refused and nobody disconnected, but a player
who asks three times the rate of searches or invites is). A player can come back under a new id at each connection,
so the limits of one address and of one invited player are the ones that hold:

| Limit | Default | |
|---|---|---|
| `players` | 500 | players connected at once |
| `connectionsPerAddress` | 4 | connections from one address at once (an IPv6 one counts by its /64) |
| `lobbiesPerPlayer` | 4 | lobbies one player is in at once |
| `lobbiesPerAddress` | 8 | lobbies the players of one address own at once (an IPv6 one counts by its /64) |
| `joinsPerMinute` | 20 | lobby joins per player (a join of a lobby gone or full counts) |
| `joinsPerAddress` | 20 | lobby joins of the players of one address |
| `membersPerLobby` | 8 | the largest lobby |
| `matches` | 250 | matches the relay's host cores run at once, all of them together; past it a custom lobby's start is refused and the queue holds its tickets, nobody disconnected |
| `matchesPerAddress` | 16 | bounds nothing now (no player opens a match on the relay); still read, so an older config starts |
| `searchesPerMinute` | 60 | lobby searches per player, refused past it (a player queueing searches about 20 times a minute per mode; the custom game browser 4 times a minute, more while its SEARCH is pressed) |
| `invitesPerMinute` | 20 | invites per player |
| `invitesPerAddress` | 30 | invites of the players of one address |
| `invitesToPlayer` | 10 | invites one player is sent a minute, at most half of them at once |
| `inviteAgainMs` | 15000 | after an invite, the next from that player to the same one waits this long |
| `presenceEveryMs` | 1000 | a player's online list entry changes at most once in this long (a sooner change is refused, nobody disconnected) |
| `whoPerMinute` | 12 | online list asks per player, refused past it (an asker is never disconnected for them) |
| `whoPerAddress` | 30 | online list asks of the players of one address (an IPv6 one counts by its /64) |
| `controlPerSecond` | 50 | lobby and keepalive messages per player |
| `messageBytesPerSecond` | 131072 | bytes per player of messages |
| `matchBytesPerSecond` | 262144 | bytes per player of a match's packets (past it packets are lost, not the player) |
| `frameBytes` | 65536 | the longest message |
| `packetBytes` | 1170 | the longest packet |
| `helloMs` | 10000 | a new connection's time to sign in |
| `silentMs` | 20000 | a connection that sends nothing this long is closed |
| `sendBufferBytes` | 1048576 | data waiting for a player who reads too slowly; past it the player is disconnected |

The first start writes every limit into the file; a release that changes a default does not change a file that
is already there. Delete a line to take the default again. An unknown limit or a value that is not a number above 0
stops the program with the reason.

## What goes wrong

- **Players cannot reach it** (the launcher's line beside the address says no answer): the port is not forwarded,
  or a firewall blocks it. Check from outside your network (a phone off Wi-Fi, a friend); from inside, many routers
  do not let a PC reach its own outside address, so test with the PC's own address there.
- **"port 7777 is in use by another program":** another relay or program has it; stop it, or pick another port
  (`--port`, or `port` in the config) and forward that one.
- **"wire version ...":** the player's launcher and the relay are of different releases; update the older one.
  A relay does not need to be updated for each game release, only when the relay's wire changes. Wire 3 (the
  online list and its settings) refuses the launchers of wire 2 and before, and theirs a relay of wire 2.
- **Matches lag or stutter for everyone:** UDP does not get through (forward UDP too), or the relay's connection
  is too slow for its players. Each player in a match sends about 60 small packets a second to each other player.
- **"signed in elsewhere":** the same launcher connected again (a second copy of the game on one PC); the first
  connection is closed.
- **A player is disconnected with "too many ..."**: they passed a limit. Raise it in the config if real players
  meet it.
- **"mvs-relay: ...mvs-relay.json: unknown field "registery" is ignored"** (on stderr, at the start): the config
  has a top-level field the relay does not read, often a misspelled one. The relay starts without it; fix the name.
- **Behind the ISP's own NAT** (the router's outside address is `100.64.x.x` to `100.127.x.x`, or a private one):
  no port forward reaches the PC from the internet; run the relay on a rented server instead.
