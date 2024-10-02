# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

## [0.13.1] - 2024-10-02
### Changed
- sawp-modbus: Make length field of Message public

### Fixed
- sawp-resp: Fix crash with negative length arrays triggering a massive memory allocation
- sawp-resp: Override Probe to reject when Invalid is the only message. The default implementation caused all data to always be interpreted as RESP.
- sawp-error: Fix cfg lines to correctly use feature name

## [0.13.0] - 2024-07-08
### Changed
- sawp: increased MSRV to 1.63.0
- sawp: Remove Cargo.toml deps which served to pin MSRV compatible transitive dependencies
- sawp: derive Eq where PartialEq is already derived and Eq could be derived (applied from clippy lint)
- sawp: Include Cargo.lock to help deliver on our MSRV promise
- sawp-file: Update to rmp-serde 1.1.1
- sawp: Applied clippy lints
- sawp-diameter: error flags now use sawp\_flags, changing from a struct to an enum.

### Fixed
- sawp: Fix release pipeline to verify MSRV, not stable

## [0.12.1] - 2023-04-12
### Fixed
- sawp-ike: Restricted lengths for attribute parsing to prevent buffer over-reads
- sawp: Pin criterion dependencies to maintain our MSRV promise
- sawp: Remove unused key from release.toml which caused build failures


## [0.12.0] - 2023-02-13
### Added
- sawp-ike: initial release of protocol parser
- sawp: added ip types to the C/C++ FFI

### Changed
- make: compose directories from $DESTDIR at usage time instead of preformatting LIBDIR and INCLUDEDIR with it
- sawp: apply clippy lints
- sawp: increase MSRV to 1.58.1
- sawp: change to 2021 edition
- sawp: update to nom 7.1
- sawp: unpin half version
- sawp-file: unpin rmp version

### Fixed
- make: pkgid cut updated for latest version
- make: link to correct artifact
- sawp: impl Display for Error (was todo!)
- sawp-dns: use binary strings instead of taking as\_bytes() of a string
- sawp-dns: parse zero-label names as empty string instead of failing
- sawp-flags: derive Eq on enums when PartialEq is derived
- sawp-modbus: breaking API change - get\_write\_value\_at\_address now takes address by value.
- sawp-pop3: limit keyword count which prevented publishing
- sawp-pop3: more restrictive keyword and status matching

## [0.11.1] - 2022-06-21
### Fixed / Changed
- modbus: fix integer overflow in address and quantity

## [0.11.0] - 2022-05-27
### Fixed / Changed
- modbus: make parser fields public

## [0.10.0] - 2022-05-20
### Fixed / Changed
- modbus: add option for strict probing
- derive: pin proc-macro-crate to v1.1.0
- file: pin rmp to 0.8.10
- azure: fix use of cargo release

## [0.9.0] - 2022-02-07
### Added
- sawp-pop3: initial release of protocol parser.
- sawp-ffi: add helper function for nested containers.
- make: add version target.
- doc: add french translations.
- docker: add Dockerfile.

### Fixed / Changed
- azure: pipeline improvements.
- sawp: clippy updates.
- make: fix symlinking issue in install target.

## [0.8.0] - 2021-11-10
### Added
- makefile: install target
- sawp-tftp: option extension parsing

### Fixed / Changed
- cargo: force dependency to half 1.7

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
[Unreleased]: https://github.com/CybercentreCanada/sawp/compare/sawp-0.13.1...HEAD
[0.13.1]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.13.1
[0.13.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.13.0
[0.12.1]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.12.1
[0.12.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.12.0
[0.11.1]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.11.1
[0.11.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.11.0
[0.10.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.10.0
[0.9.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.9.0
[0.8.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.8.0
[0.7.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.7.0
[0.6.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.6.0
[0.5.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.5.0
[0.4.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.4.0
[0.3.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.3.0
[0.2.0]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.2.0
[0.1.1]: https://github.com/CybercentreCanada/sawp/releases/tag/sawp-0.1.1
