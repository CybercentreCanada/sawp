# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

## [0.7.0] - 2021-09-24
### Added
- sawp-resp: initial release of protocol parser.

### Fixed / Changed
- sawp: updated style guide in CONTRIBUTING.md.
- sawp: specified compatible criterion version.
- sawp-diameter: specified compatible bitflags version.

## [0.6.0] - 2021-06-15
### Added
- sawp-gre: initial release of protocol parser.
- sawp-dns: initial release of protocol parser.
- sawp-tftp: add ffi support.

### Fixed / Changed
- sawp-ffi: use size_t instead of uintptr_t for size types across all ffi modules.
- sawp-ffi: set soname in ffi shared object libraries.

## [0.5.0] - 2021-05-07
### Added
- sawp-ffi: added getter by index for vecs.

### Fixed
- sawp-modbus: `WriteMultipleCoils` parsing divided the request's count by 8 instead of the quantity.

## [0.4.0] - 2021-04-12
### Added
- sawp-modbus: re-export `sawp_flags::Flags` so sawp-flags doesn't need
  to be added to Cargo.toml.
- sawp-flags: add `is_empty()` and `is_all()` helper functions.

## [0.3.0] - 2021-04-09
### Fixed
- various pipeline improvements for rpm deployment, publishing packages,
  doc tests, memory checks, build and clippy warnings.

### Added
- sawp-ffi: added support for option, string, vec and flags.
- sawp-flags-derive: initial release of bitflags handling and storage
  derive macros.
- sawp-flags: initial release of bitflags handling and storage crate.
- sawp-modbus: added ffi support for error flags.
- sawp-modbus: use new sawp-flags crate.
- sawp-diameter: added parsing of avp data types.
- sawp-tftp: initial release of protocol parser.

## [0.2.0] - 2021-02-22
### Fixed
- sawp-ffi: missing version number was preventing cargo publish.
- sawp: verbose feature was not being used by protocol parsers.
- sawp-modbus: added error flag for handling invalid protocol instead of failing
  to parse the message.
- sawp-modbus: made probing function more strict by failing if any validation
  flags are set.
- sawp-modbus: added min and max length checks for better recovery when invalid
  lengths are provided. 

### Added
- sawp: support for building an rpm with all FFI libraries and headers.

## [0.1.1] - 2021-02-12
### Added
- sawp: initial release containing common traits and types used by protocol parsers.
- sawp-modbus: initial release of our first complete protocol parser. Integration
  was tested with suricata.
- sawp-diameter: initial release of a protocol parser (todo: add missing AVPs for mobility).
- sawp-json: initial release of a protocol parser (todo: use for 5G protocols).
- sawp-file: initial release for logging and debugging SAWP API calls (todo: not in use yet).
- sawp-ffi: initial release of FFI helper macros and traits.
- sawp-ffi-derive: initial release for generating FFI accessor functions.
- sawp-modbus: FFI support.

<!-- next-url -->
[Unreleased]: https://github.com/CybercentreCanada/sawp/compare/sawp-0.7.0...HEAD
[0.7.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.7.0
[0.6.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.6.0
[0.5.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.5.0
[0.4.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.4.0
[0.3.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.3.0
[0.2.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.2.0
[0.1.1]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.1.1
