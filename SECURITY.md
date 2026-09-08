# Security & responsible use

RailKey is a 125 kHz RFID **fuzzer**: it emulates access-control cards toward a
reader in a smart order. It is intended for authorized security testing,
education, and research.

## Authorized use only

Use RailKey only against readers and systems that:

- you personally own, **or**
- you have **explicit written permission** to test (e.g. a signed penetration-
  testing engagement or a lab you administer).

Testing access-control systems without authorization is illegal in most places.
The maintainers do not condone, and are not responsible for, misuse.

## What it does and does not do

- It **emits** EM4100 / HID (H10301) / Indala 125 kHz sequences you configure.
- It does **not** read, log, store, or transmit anyone's captured card data.
- The bundled dictionary is limited to the generic **default/test** values that
  every RFID fuzzer already ships — not real facility credentials.

## Scope of the "efficiency" claim

RailKey reduces the *number of transmissions and the field time* needed to cover
a search space, by:

- Gray-code ordering (minimal modulation-buffer change between IDs),
- structure-aware HID generation (valid-parity Wiegand codewords only),
- neighborhood-first search around a known-good seed.

It does **not** defeat cryptographic credentials. 13.56 MHz cards (Mifare,
DESFire, etc.) use challenge/response and are explicitly out of scope — LF
125 kHz protocols are unauthenticated, which is exactly why they are fuzzable
and why deployments relying on them should be upgraded.

## Reporting

Found a bug or a safety concern with the tool itself? Open an issue on the
repository. Do not use issues to share real credentials or details of systems
you tested.
