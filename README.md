# Security Aware Wire Protocol parsing library.

This library contains parsers for various wire protocols,
and is intended to be used in network security sensors.

Each parser exposes a common interface that allows the sensor
engine to feed bytes into the parser and receive parsed
metadata back. The bytes are expected to be at the session layer,
so the engine is responsible for assembling transport layer
data into a session payload, which is then fed into this library.

The interface to each parser is uniform and simple, consisting of
only a few functions to:

- test that a payload is or is not the protocol in question
  (eg. is this modbus?)
- provide more bytes to the parser
- set callbacks to invoke on per-protocol metadata events
- indicate that some bytes are unavailable (ie. notify of packet
  loss)
- indicate a session has ended

The library exposes Rust and C bindings for easy integration into
existing and future network security sensor platforms.
