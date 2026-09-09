# RailKey

An efficient 125 kHz (LF) RFID access-control fuzzer for the Flipper Zero,
built for **authorized** security testing and research.

> RailKey emulates 125 kHz cards toward a reader you control, in a smart order,
> to help you audit access-control systems you own or are contracted to test.
> It is a defensive/research tool. See [Legal & authorized use](#legal--authorized-use).

## Why another RFID fuzzer

Most Flipper RFID fuzzers do the same two things: play a small list of default
card values, or brute-force a byte by incrementing it with a fixed dwell time.
That wastes an enormous amount of the operator's time in the field. RailKey
keeps the familiar workflow but changes the *order* and *shape* of what it
sends:

| Typical fuzzer | RailKey |
| --- | --- |
| Linear increment, fixed dwell | **Gray-code ordering** — consecutive IDs differ by ~1 bit, so the LF modulation buffer is re-shaped minimally between transmissions |
| Byte brute-force ignores card structure | **Structure-aware HID (Wiegand H10301)** — iterates facility x card number and lets the encoder produce valid-parity codewords, instead of burning cycles on unrepresentable raw bytes |
| Blind sweep of the whole space | **Neighborhood mode** — seed one known-good card and it tries adjacent card numbers first (sequential badge issuance means a valid card's neighbors are the likeliest hits), then single-bit flips of the 24-bit payload |
| One protocol per run | **Multi-protocol interleave** — EM4100 / HID / Indala for each logical ID in a single pass, for when you don't yet know the target's tech |
| Restart from zero | Live attempts / rate / ETA and a bounded, resumable-by-design job model |

The interesting logic lives in [`railkey_engine.c`](railkey_engine.c), which is
deliberately free of firmware headers so the sequence generators can be reasoned
about (and unit-tested) on their own.

## Modes

- **Dictionary sweep** — plays a curated dictionary of *generic factory/test*
  and low-issuance seed values as a fast first pass. Pick which dictionary in
  Settings (see [Dictionaries](#dictionaries)): **All formats**, **HID Prox 26**,
  **EM4100 fob**, or **Indala 26**.
- **HID smart sweep** — H10301 facility x card. Fix a facility, or sweep all 256.
  Card numbers are emitted in Gray-code order.
- **EM4100 gray sweep** — 16-bit card counter in Gray order with a fixed prefix.
- **Multi-protocol** — interleaves EM4100 / HID / Indala per logical ID.
- **Neighborhood (HID)** — enter a 2-byte card number as the seed; RailKey emits
  the seed, then +/- N adjacent cards, then Hamming-1 bit flips.

## Settings

- **Dwell (ms)** — emulate time per ID (40–300). Lower = faster, but the reader
  needs long enough to sample; tune to the target.
- **HID facility** — facility used when not sweeping (0–255).
- **HID fac sweep** — sweep all facilities in HID smart mode.
- **Neighbor +/-** — radius for neighborhood mode.
- **Dictionary** — which dictionary the Dictionary sweep uses.

## Dictionaries

The dictionary sweep is split into one list per 125 kHz format, so you can
aim it at the class of reader you are authorized to test. They are ordered by
how commonly each format turns up, and the **All formats** option runs them in
that order:

| Dictionary | Format | Typically seen on |
| --- | --- | --- |
| **HID Prox 26** | HID H10301 26-bit | commercial / office access readers |
| **EM4100 fob** | EM4100 / EM410x | residential fobs, intercoms, gyms, amenities |
| **Indala 26** | Indala 26-bit | legacy installs |

Every entry is a **generic factory default, published sample, or low-issuance
seed** — the same class of "default values" every RFID fuzzer ships. **None are
real facility credentials, and none are tied to any specific site.** They just
clear the obvious defaults quickly before you fall back to the structured
sweeps (HID smart / EM gray / neighborhood), which are the exhaustive path. The
lists live in [`railkey_engine.c`](railkey_engine.c) — add formats or seeds
there. Use only on readers you own or are authorized to test.

## Build

There is no local toolchain requirement — CI builds the `.fap` for you.

**From CI:** every push runs the [Build FAP](.github/workflows/build.yml)
workflow (`ufbt` against the official release SDK). Download `railkey-fap` from
the run's **Artifacts**.

**Locally (optional)**, with [ufbt](https://github.com/flipperdevices/flipperzero-ufbt):

```bash
pip install --upgrade ufbt
ufbt update --channel=release
ufbt              # build -> .ufbt/build/railkey.fap
ufbt launch       # build + install to a connected Flipper
```

## Try it in the browser

RailKey also runs in the datarail.org Flipper Zero emulator at
**datarail.org/flipperzero** (select **RailKey**, press *Boot the app*). That
build is [`emu/railkey_emu.c`](emu/railkey_emu.c) — a shim-compatible front end
that renders on the 128x64 canvas and drives the **same**
[`railkey_engine.c`](railkey_engine.c) the hardware app uses, so you watch the
real Gray-code / structure-aware ordering step by step. No RF is transmitted in
the browser — the emulator has no radio.

## Install

Copy `railkey.fap` to `SD Card/apps/RFID/` on the Flipper (via qFlipper or the
mobile app). It appears under **Apps → RFID → RailKey**.

## Legal & authorized use

RailKey transmits credentials to access-control readers. Do that **only** on
systems you own or have **explicit written authorization** to test. Unauthorized
use against access-control systems is illegal in most jurisdictions.

The bundled dictionary contains only the class of *default/test* values that
ship in every fuzzer — not real facility credentials. RailKey does not read,
store, or exfiltrate anyone's card data; it emits sequences you configure.

You are responsible for how you use this. See [LICENSE](LICENSE) — no warranty.

## Layout

- [`application.fam`](application.fam) — Flipper app manifest
- [`railkey.c`](railkey.c) — UI (view dispatcher), fuzz worker thread, LFRFID glue
- [`railkey_engine.c`](railkey_engine.c) / [`railkey_engine.h`](railkey_engine.h) — sequence generators (pure C)
- [`railkey.h`](railkey.h) — shared types
- [`emu/railkey_emu.c`](emu/railkey_emu.c) — browser-emulator front end (shim-compatible, reuses the engine)
- [`.github/workflows/build.yml`](.github/workflows/build.yml) — CI build
