# Rust crates

The Cargo workspace (`Cargo.toml` at the repo root, `rustfmt.toml` beside it) that holds the whole program: the
launcher and its import, the game, and the relay. The game was first written in TypeScript and ported crate by crate;
that TS game, the oracle, is not published. Its per-tick traces and tapes are what the Rust sim was checked against
bit for bit, and the sim's own traces are the regression check since. Without the oracle's recordings, the tests
that compare against them skip and say so.

## The crates

| Crate | What |
|---|---|
| **The program** | |
| `mvs-app` | the game's program: the window, input, the match loop, the menus' flow, online glue; the `mvs` and `mvs-launcher` binaries |
| `mvs-settings` | the player's settings file and stats file in the data folder |
| `mvs-load` | the loader's worker threads: loads built off the frame thread |
| `mvs-release` | what a release is: its version, the update feed, the files a release folder holds |
| `mvs-dist` | the release tool: builds and packs a release, guards its zips, serves a local feed for the update check |
| **The import** | |
| `mvs-pak` | the beta's paks: index, AES, zlib, mounts, and the check of the player's copy |
| `mvs-uasset` | UE 4.26 cooked packages: summary, imports, tagged properties, the native classes the import reads |
| `mvs-import` | the kinds built from the player's paks into the store, and the development CLI over them |
| `mvs-store` | reads the store the import wrote: the manifest, one pack per kind, an entry by its path |
| **The match** | |
| `mvs-sim` | the match simulation: the World, its fighters, actors, buffs and the match's flow, stepped once per tick |
| `mvs-sim-derive` | `derive(State)` for the sim's rollback state: field-by-field `clone_from` and the desync hash |
| `mvs-mutators` | the Chaos Wheel's mutators: each one's key, tier and where it may be picked |
| `mvs-data` | the game's bound data as the sim reads it: fighters, stages, perks, items |
| `mvs-stage` | custom stages, the port's own: a layout over a base stage and the map's stage data composed from it |
| `mvs-stage-editor` | the stage editor, a dev program: a layout's stage in a window with its play shapes over it, its pieces picked, moved, copied and deleted with the mouse and egui panels, saved and test played |
| `mvs-math` | the sim's math: the build's own float32 routines, bit for bit |
| `mvs-math-check` | long checks of `mvs-math` against a reference and the beta exe's routines, run on request |
| `mvs-anim` | the clip decoder and pose sampler, the sim's skeleton pose and montage player |
| `mvs-collision` | the sim's geometry queries: sweeps, edges, rigid bodies, hit and hurt overlaps, the stage solids |
| `mvs-trace` | the per-tick trace of a match: the record, its file, the reader, the writer and the compare |
| `mvs-sim-trace` | the Rust side of the trace: the World as the trace's record, a frame loaded back, the `sim-trace` runs |
| `trial-tape` | reads the oracle's tapes (below) |
| **Drawing and sound** | |
| `mvs-view` | what the renderer draws a tick with, GPU-free: the posing, the camera, the frame input |
| `mvs-vfx` | the Cascade particle player on the CPU |
| `mvs-material` | the material kind (cooked shaders, uniform expressions, parameters, textures) for the renderer |
| `mvs-d3d` | the Direct3D 11 and DXGI items the renderer and UI name: the `windows` crate's on Windows, bindings for DXVK-native on Linux |
| `mvs-render` | the renderer on Direct3D 11 with the build's cooked shaders |
| `mvs-ui` | the UI: a Slate subset over the build's widget trees, its text, the HUD, the menus and the launcher's screens |
| `mvs-freetype` | FreeType 2.10.0 (the build's version), vendored and built from source, with the calls the UI's text makes |
| `mvs-audio` | the game's sound: a Wwise interpreter over the soundbanks, the mixer and its output |
| **Online** | |
| `mvs-protocol` | what the game, the host core and the relay share: lobby rules, a match's packets and referee, the relay's wire |
| `mvs-net` | online play: rollback over the deterministic sim, the input codec, the links (in-memory, relay, LAN, Epic) |
| `mvs-host` | the host core: the rules of one online session, run by the player who hosts it |
| `mvs-relay` | the relay anyone may run: lobbies, searches, invites, the links that carry packets, the referees |
| `mvs-registry` | the registry relays check in to, and its pages for adding and refusing relays |
| **Experiments** | |
| `trial-light` | UE 4.26's own deferred lighting and tonemapper from the global shader cache over a captured G-buffer |

## Tapes

A tape is the calls one piece of the TS sim made in a real run, with their results. The oracle records it, the Rust
side replays it (`trial-tape`) and compares every result.

- File: `"MVTAPE01"`, u32 header length, the header (UTF-8 JSON: `slice`, `source { commit, run }`, `calls [{ id,
  name, layout }]`, `fixtures`), then records to the end: u16 call id, u16 0, u32 payload length, the payload (the
  call's values little-endian, as its `layout` says).
- **Fixtures:** the build data the piece reads (clip bytes, a skeleton, a stage's solids), written beside the tape.
  Fixtures and tapes hold the build's data, so they are never committed.
- **Checking:** every float result the same bits, or both NaN (`same_bits`); every integer and flag equal. A tape
  that does not pass is a bug in the port, found and fixed, never a tolerance.

## Rules

- Sim crates compute with `mvs-math`, never `f32::sin` and the like from the platform's libm. No `unsafe` in a sim
  crate. A map iterated in insertion order stays in insertion order.
- Comments follow `docs/code-style.md`.
- A crate's binary lives in `src/bin/` (`.gitignore` lets `crates/*/src/bin/` through its `**/bin/`).
- A fixture read from JSON needs serde_json's `float_roundtrip` feature: without it some f64 come back 1 ulp off.
- windows-rs `ID3D11DeviceContext::GetData` turns S_FALSE into `Ok`: a timestamp query is polled through the vtable.
