# [Français](README.fr.md)

# Security Aware Wire Protocol parsing library.

This library contains parsers for various wire protocols,
and is intended to be used in network security sensors.

Each parser exposes a common interface that allows the sensor
engine to feed bytes into the parser and receive parsed
metadata back. The bytes are expected to be at the session layer,
so the engine is responsible for assembling transport layer
data into a session payload, which is then fed into this library.

This library aims to be resilient and parse as many messages as 
possible that are seen in the wild. If a message is invalid or
out-of-spec, it should not be discarded by the parser. Parsers
will set flags on the message when it fails validation instead
of returning an error.

The interface to each parser is uniform and simple, consisting of
only a few functions to:

- test that a payload is or is not the protocol in question
  (eg. is this modbus?)
- provide more bytes to the parser
- set callbacks to invoke on per-protocol metadata events (todo)
- indicate that some bytes are unavailable (ie. notify of packet
  loss) (todo)
- indicate a session has ended (todo)

The library exposes Rust and C bindings for easy integration into
existing and future network security sensor platforms. (todo)

# Usage
Start using SAWP by including a parser in your project's `Cargo.toml`
dependencies. The base library will also be required for using common
types.

**The minimum supported version of `rustc` is `1.58.1`.**

## Example
```
[dependencies]
sawp-modbus = "0.12.1"
sawp = "0.12.1"
```

## FFI Support
Some parsers have a foreign function interface for use in C/C++ projects.
FFI Support can be enabled by building with the `ffi` feature.

A [Makefile](Makefile) is also provided to ease the build process. Please refer to this file for more in-depth documentation.

```
# Install cbindgen which is required to generate headers
cargo install --force cbindgen

# Build headers and shared objects
make
```

# Contributing

This project is actively maintained and accepting open source
contributions.  See [CONTRIBUTING](CONTRIBUTING.md) for more details.
