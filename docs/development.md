# Developing MVS Classic

How to build the game from source, build its content from your copy of the beta, run it and check a change. The
crates are listed in `crates/README.md`; the rules for a change are in `AGENTS.md`.

## What you need
- Windows 10 or 11, 64-bit, with a Direct3D 11 graphics card.
- Rust (stable) and the Visual Studio C++ build tools.
- On Linux instead: podman or docker; the build runs in a container (below). Packing a release on Linux needs more,
  listed under "Pack a release on Linux".
- The 2023 open beta, downloaded through the Steam console as the README's "Install" shows. The tools read its paks
  where Steam put them and never change them.

## Point the tools at your beta
Create `content/local.json` (the `content/` folder is ignored by git):

```json
{ "paks": "C:/Program Files (x86)/Steam/steamapps/content/app_1818750/depot_1818751/MultiVersus/Content/Paks" }
```

with the path of your own `depot_1818751`. The importer reads the paks' key from the beta's exe beside them; it is
never typed in or printed. The release tool's guard reads the key the same way, or from `MVS_PAK_KEY`.
`mvs-import setup <paks dir>` checks that a folder holds the build the port expects.

## Build the store
The game never reads the paks while it runs: the import builds everything it uses into a store, one pack per kind.
A player's launcher does this once; a developer builds the dev store in `content/.store`:

```
cargo run --release -p mvs-import -- import --store content/.store
```

A later run rebuilds only the kinds whose code or source changed (`--kind <id>` builds one, `--force` all). The tools
and tests find the dev store by themselves; `CONTENT_STORE=<dir>` points them at another one.

## Run it
- `play.bat` builds the launcher and the game and opens the launcher on the dev store, at its Home: PLAY starts the
  game. `play.bat --play` goes straight into the game. Arguments the launcher does not know go on to the game, for
  example `play.bat --size 1920x1080 --no-audio`.
- The launcher's Home shows the latest releases' patch notes: the text of each release on GitHub, read from the
  list of releases beside the update feed and kept in the data folder (`patch-notes.json`). A dev build has no
  update feed and shows none; set `MVS_NOTES_FEED` to a list's address
  (`https://api.github.com/repos/<owner>/<repo>/releases`) to see them. To see how a release's text will read
  before it is published, write it into a file and draw the launcher's screens with it:
  `cargo run --profile trace -p mvs-ui --bin launcher-shots -- --out <dir> --store content/.store --notes <file>`
  (the file's shape is in the tool's header). A `## Download` section is the page's and is left out.
- `mvs --free-cam [<yaw>,<pitch>,<zoom>]` (dev, any match) draws through a free camera: an orbit about the point the
  game's lens looks at. The optional start is degrees, degrees and a distance factor (`90,5,1.4` is the side view;
  `0,0,1`, the default, is the game's own). Mouse: right-drag orbits, middle-drag or Shift + right-drag pans, the wheel
  zooms. F8 turns the keys on and off; while on, the keyboard drives the camera and no fighter: WASD or the arrows
  orbit and tilt, Q / E zoom, R back to the game's view, F follows the fighters or holds the pivot where it is.
- `mvs --test-3d` (dev, a local match: the Lab, Local Play, the command line's match; `play.bat --play --test-3d`
  passes it through the launcher) is a feel test of 3D movement (`mvs_sim::world::depth3d`). The 2D fight runs in a
  vertical plane through the stage's middle that turns toward the line through the first two fighters (at most 240
  degrees a second), and the camera turns with it. Each fighter steps off the plane: E toward the camera, Q away
  from it, or on a pad L3 held with the left stick up (away) and down (toward); a fighter with its hit boxes out does
  not step. A hit needs the two depths within 110 cm (a projectile keeps its owner's depth at its spawn), so a
  sidestep dodges. The bot does not strafe; the stage's edges and blast box stay the 2D plane's, the depth is held
  within 700 cm of the middle. Effects placed from the sim's x (not on a fighter's bones) stay on the 2D plane.

It builds the `trace` profile: release code built incrementally, so a rebuild after a small change takes seconds,
not minutes. `--release` is for timings and what ships.

`tools/cargo-slot.ps1` runs cargo when one of a few build slots is free, at low priority, so several builds at
once (worktrees, agents) queue instead of taking the whole machine. Plain `cargo` works too.

## Build on Linux
`tools/linux-build.sh` builds in the Steam Runtime "sniper" SDK container, with podman or docker, so what it builds
needs glibc 2.31 at most and runs on a Steam Deck and on ordinary desktop distributions. The renderer runs on
DXVK-native, which turns Direct3D 11 into Vulkan.

- `tools/linux-build.sh deps` builds DXVK-native at the version the script pins into `target/linux-deps/dxvk`. Run
  it once, and again when the pin changes.
- `tools/linux-build.sh cargo <args>` runs `cargo <args>` in the container, with the target dir
  `target/linux-sniper`; for example `tools/linux-build.sh cargo test --profile trace -p mvs-sim`. The first run
  installs the compiler `rust-toolchain.toml` names into a container volume that later runs reuse. Tests that need
  a GPU or a window skip in the container, which has neither.
- `tools/linux-build.sh release` builds the launcher and the game for release and lays out the release folder in
  `target/linux-release`: `MVSC Launcher` at the top, and in `game/` the game (`MVS Classic`), DXVK's and SDL3's
  libraries, `online.json`, their licenses and `linux-build.json` (the version and both programs' SHA-256). It
  fails if anything in the folder needs a glibc newer than 2.31. `MVS_VERSION` sets the programs' version.

### Pack a release on Linux
On Linux, `cargo run --release -p mvs-dist -- build --version <x.y.z>` makes the whole release: the Windows and
Linux game zips and the relay's zip. It builds the Linux game and relay in the container (`--game-linux` and
`--relay-linux` take ones built elsewhere) and the Windows programs on the host through `tools/windows-cross.sh`,
which needs:

- Rust through rustup on the host (`mvs-dist` runs there too), with the Windows target for the pinned compiler:
  `rustup target add x86_64-pc-windows-msvc --toolchain <the rust-toolchain.toml channel>`;
- LLVM's `clang-cl`, `llvm-lib` and `lld-link`;
- a splat of Microsoft's CRT and Windows SDK at `~/.cache/xwin/splat` (or `XWIN_SPLAT`), made with
  `xwin --accept-license splat`. Running that accepts Microsoft's license terms for those files, which is yours to
  do: the script never runs it.

The self check runs the Windows game under Wine, so Wine is needed too, in a prefix of its own beside the output
folder that is removed at the end; your own Wine prefix is not touched. `--eos` takes the EOS SDK's libraries from
the repo's `third_party/eos` (`MVS_EOS_DLL` and `MVS_EOS_SO` name other copies of the Windows DLL and the Linux
library) and the credentials from `MVS_EOS_CREDENTIALS`. The guard reads the paks' key as shown under "Point the
tools at your beta". `release-check` tests the Windows updater and needs Windows.

The releases on the repo's Releases page are packed on GitHub instead, as "Make a release" shows. Every push to a
branch also builds a Linux test build (no EOS files, not a release): when the run's tests passed, open the run on
the repo's Actions tab and download `mvs-classic-linux` under "Artifacts".

### Make a release
A release is packed on GitHub from the programs GitHub already built and tested for the commit you tag; nothing is
built again for it. [`build.yml`](../.github/workflows/build.yml) builds every push to every branch, and
[`release.yml`](../.github/workflows/release.yml) packs the release when a version tag is pushed. Their header
comments say what each step does and why.

1. Set the version in `Cargo.toml` (`version` under `[workspace.package]`, `0.2.0` say) and commit it with the rest
   of the release's code.
2. On that clean tree, make the self check's reference for that code, `self-check.json`:
   - on Windows, `powershell -NoProfile -File tools/self-check.ps1 -Version 0.2.0`;
   - on Linux, `pwsh -NoProfile -File tools/self-check.ps1 -Version 0.2.0`, with PowerShell (`pwsh`) installed and
     `tools/linux-build.sh deps` run first.

   The script refuses to run while the code has uncommitted changes, because the release checks that the code has
   not changed since the commit that holds `self-check.json`, and not in that commit either: commit the code first,
   then `self-check.json` on its own. Push; `build.yml` builds that commit.
3. Tag the commit and push the tag: `git tag v0.2.0 && git push origin v0.2.0`. Both can be pushed together:
   `release.yml` waits for the commit's build if it is still running. A suffix (`v0.2.0-test1`) makes a
   prerelease: a test tag. For one, `Cargo.toml`'s version must be `0.2.0-test1` exactly (step 1 and
   `self-check.json` are made for it), and the zips are named by it. The updater never offers it.
   A tag that already has a release, a draft included, is refused before anything runs: delete that release (and
   the tag, if it is to move) first.
4. When `release.yml` has run, the release is a draft on the repo's Releases page: three zips (the Windows game, the
   Linux game, the relay for both), a `.sha256` beside each and `SHA256SUMS`. Check it, then publish it there
   (Edit, then "Publish release") or with `gh release edit v0.2.0 --draft=false`.

The game's updater offers only the newest published release that is not a prerelease, so players never see a draft
or a prerelease.

The release needs two secrets, set in the repo's Settings, then "Secrets and variables", then "Actions". Either one
missing stops the release, by name.

- `EOS_CREDENTIALS`: the text of `eos.json`, as it is. The game reads it to sign in to Epic's online services, and
  it goes into both game zips. Its client id and secret are hidden in the run's logs.
- `MVS_PAK_KEY`: the paks' key, 64 hex digits. It is never packed: the guard searches every zip for it and refuses a
  zip that holds it.

An attestation is GitHub's signed record of where a file was made and from which commit; the README's "Check a
release's programs" shows how anyone checks one (pinning the signing workflow and the ref, as
`gh attestation verify <file> --repo <owner>/<repo> --signer-workflow <owner>/<repo>/.github/workflows/release.yml
--source-ref refs/tags/v0.2.0`; for a program, `build.yml` and `refs/heads/<default branch>`). A tag on a commit
that was pushed only to another branch (a testing branch, say) still makes a release. Its zips are attested, but its
programs are not: `build.yml` attests the programs only when it builds them for a push to the default branch. The
release's notes say which.

### When you change Direct3D code or HLSL
The Linux build needs two things that Windows makes for itself. Both are files in the repo, made again by a command
when the code changes, and the Linux check on GitHub fails until they are.

- **A D3D11, DXGI or Direct3D item the port has not used before** (an interface, a struct, a constant, a function):
  add its Win32 metadata name to `crates/mvs-d3d/names.txt`, in the form the file already uses (for example
  `Windows.Win32.Foundation.RECT`), then run

  ```
  cargo run --manifest-path tools/d3d-bindings/Cargo.toml
  ```

  It rewrites `crates/mvs-d3d/src/linux/bindings.rs`, on Windows or Linux alike. Commit both files. Until then the
  Linux build cannot find the item and names it. `-- --check` after the same command only compares, which is what
  the Linux check runs.
- **A change to the port's own HLSL** (the shaders `mvs-render` and `mvs-ui` compile): Linux has no `D3DCompile`, so
  it loads the DXBC that Windows made of each shader, committed in `crates/mvs-render/shaders/` and
  `crates/mvs-ui/shaders/` with a `keys.txt` that ties each blob to its source. After the edit, on Windows, for each
  of the two crates whose shaders changed (here `mvs-render`), in PowerShell:

  ```
  $env:MVS_WRITE_DXBC = 'C:\temp\dxbc-render'
  cargo test -p mvs-render the_committed_dxbc_is_what_d3dcompile_makes
  Remove-Item Env:MVS_WRITE_DXBC
  ```

  That run writes every blob and `keys.txt` into the folder and then fails on purpose ("written, run again without
  MVS_WRITE_DXBC"). Replace the `.dxbc` files and `keys.txt` in `crates/mvs-render/shaders/` with the ones written,
  and run the same `cargo test` again: it passes when the committed blobs are what `D3DCompile` makes. Until then
  that test fails on Windows, and `every_listed_shader_has_its_blob` fails on Linux and in the Linux check.

## Check a change
- `cargo fmt --check` and `cargo clippy --release --all-targets`: no new warning.
- `cargo test --profile trace --no-fail-fast -p <crate>` for each crate you touched. Tests that read the store use
  the dev store.
- The match code (`mvs-sim` and the crates it uses) is also checked with per-tick traces: `sim-trace` (in
  `mvs-sim-trace`) replays recorded matches from their inputs and compares the whole World, field by field, every
  tick. The recordings hold the build's numbers, so they are not in the repo; you record your own from your store.
  The matches are defined in `crates/mvs-sim-trace/matches.json` (setups, seeds and the rules that make each
  player's inputs). Before the change, on a clean checkout:

  ```
  cargo run --profile trace -p mvs-sim-trace --bin sim-trace -- --record .scratch/baseline
  ```

  After it, the same with `-- --all`: each match is stepped again with the recorded inputs and every field the
  change moved is named, with the tick and both values. A change not meant to change how a match plays leaves every
  match `same`. `.scratch/baseline` is where a plain run and the trace tests of `mvs-net` look by default; record
  it again after the store is imported again. `sim-trace --help` lists the other modes.

## Where things are
- `crates/`: the program, one crate per part (`crates/README.md`).
- `docs/code-style.md`: how code and comments are written.
- `docs/experimental.md`: the custom lobby's opt-in rules.
- `docs/registry.md`: running a registry relays check in to.
- `docs/relay.md`: running a relay.
- `online.json`: the default relay the game connects to.
