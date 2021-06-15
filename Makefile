# Build rpm for ffi releases
# ==========================
#
# Sawp packages can be built using the normal cargo workflow. Only use this
# Makefile to build a single rpm to distribute all packages that support ffi.
# Packages will be added automatically if they contain a cbindgen.toml file.
#
# The rpm repository is located in `target/rpmbuild`.
# Shared objects are located in `target/release` or `target/debug`.
# Headers are located in `target/sawp`.
#
# Example usage:
# ```bash
# # build rpm
# make rpm
# 
# # build tarball
# make package
#
# # build ffi headers and shared objects only
# make
# ```

$(eval CRATE_VERSION=$(shell (test -f Cargo.lock || cargo generate-lockfile) && cargo pkgid | cut -d# -f 2 | cut -d: -f 2))
$(eval CRATE_VERSION_MINOR=$(shell echo ${CRATE_VERSION} | cut -d. -f 1-2))
$(eval CRATE_VERSION_MAJOR=$(shell echo ${CRATE_VERSION} | cut -d. -f 1))

FFI_PACKAGES := $(patsubst sawp-%/cbindgen.toml, %, $(wildcard sawp-*/cbindgen.toml))
FFI_HEADERS := target/sawp/sawp.h $(patsubst %, target/sawp/%.h, ${FFI_PACKAGES})
FFI_OBJECTS_RELEASE := target/release/libsawp.so $(patsubst %, target/release/libsawp_%.so, ${FFI_PACKAGES})
FFI_OBJECTS_DEBUG := target/debug/libsawp.so $(patsubst %, target/debug/libsawp_%.so, ${FFI_PACKAGES})

# Source pattern to detect file changes and cache the build.
# Any source file change in the workspace should trigger a rebuild.
SOURCES := $(shell find . sawp-* -type f \( -name "*.rs" -or -name "cbindgen.toml" -or -name "Cargo.toml" \) )

# Package publication order.
# List of directories that contain a Cargo.toml file to publish.
# This is required because some packages are dependant on others.
PUBLISH := \
	sawp-flags-derive \
	sawp-flags \
	sawp-ffi-derive \
	sawp-ffi \
	. \
	sawp-modbus \
	sawp-diameter \
	sawp-tftp \
	sawp-gre \
	sawp-dns \
	sawp-json \
	sawp-file

.PHONY: env
env:
	@echo CRATE_VERSION: ${CRATE_VERSION}
	@echo CRATE_VERSION_MINOR: ${CRATE_VERSION_MINOR}
	@echo CRATE_VERSION_MAJOR: ${CRATE_VERSION_MAJOR}
	@echo FFI_PACKAGES: ${FFI_PACKAGES}
	@echo FFI_HEADERS: ${FFI_HEADERS}
	@echo FFI_OBJECTS_RELEASE: ${FFI_OBJECTS_RELEASE}
	@echo FFI_OBJECTS_DEBUG: ${FFI_OBJECTS_DEBUG}
	@echo SOURCES: ${SOURCES}

# prevents intermediate targets from getting removed
.SECONDARY: 

.DEFAULT_GOAL := all
default: all

.PHONY: all
all: headers shared_objects

.PHONY: clean
clean:
	cargo clean

# Headers
# =======
.PHONY: headers
headers: ${FFI_HEADERS}

target/sawp/sawp.h: ${SOURCES}
	RUSTUP_TOOLCHAIN=nightly cbindgen \
		--config cbindgen.toml \
		--crate sawp \
		--output target/sawp/sawp.h \
		-v \
		--clean


# for each cbindgen.toml file, call the corresponding rule to build a header file
target/sawp/%.h: ${SOURCES}
	cd sawp-$(*F) && \
	RUSTUP_TOOLCHAIN=nightly cbindgen \
		--config cbindgen.toml \
		--crate sawp-$(*F) \
		--output ../$@ \
		-v \
		--clean

# Shared Objects
# ==============
.PHONY: shared_objects
shared_objects: debug_objects release_objects

.PHONY: debug_objects
debug_objects: ${FFI_OBJECTS_DEBUG}

.PHONY: release_objects
release_objects: ${FFI_OBJECTS_RELEASE}

target/debug/libsawp_%.so: ${SOURCES} 
	cd sawp-$(*F) && \
	cargo build --features ffi --features verbose

target/release/libsawp_%.so: ${SOURCES}
	cd sawp-$(*F) && \
	RUSTFLAGS="-C link-arg=-Wl,-soname,$(@F).${CRATE_VERSION_MAJOR}" cargo build --features ffi --release

target/debug/libsawp.so: ${SOURCES}
	cargo build --features ffi --features verbose

target/release/libsawp.so: ${SOURCES}
	RUSTFLAGS="-C link-arg=-Wl,-soname,$(@F).${CRATE_VERSION_MAJOR}" cargo build --features ffi --release

# rpm
# ===
.PHONY: rpm
rpm: package
	rpmbuild -vvv -bb --define "version ${CRATE_VERSION}" --define "_topdir ${PWD}/target/rpmbuild" .rpm/sawp.spec

.PHONY: package
package: headers release_objects
	rm -rf target/rpmbuild target/_temp
	mkdir -p target/_temp/lib64
	mkdir -p target/_temp/include/sawp
	mkdir -p target/rpmbuild/
	mkdir -p target/rpmbuild/SOURCES
	for obj in libsawp.so $(patsubst %, libsawp_%.so, ${FFI_PACKAGES}); do \
		cp target/release/$$obj target/_temp/lib64/$$obj.${CRATE_VERSION}; \
	done
	cp target/sawp/*.h target/_temp/include/sawp
	tar -czvf target/rpmbuild/SOURCES/sawp-${CRATE_VERSION}.tar.gz target/_temp --transform 'flags=r;s#^target/_temp#sawp-${CRATE_VERSION}#'

# cargo publish
# =============
#
# Upload all packages in this workspace to crates.io. Uploads the dependencies
# in the right order. A sleep is used so the newly published crates can be
# fetched from crates.io.
#
# Ideally we could use a command like `cargo workspaces publish --from-git` but
# that doesn't seem to work.
.PHONY: publish
publish:
	for pub in $(PUBLISH); do \
		(cd $$pub && cargo publish && sleep 20); \
	done

.PHONY: valgrind 
valgrind:
	cargo valgrind test --workspace --all-targets --all-features

.PHONY: asan-address
asan-address: export RUSTFLAGS = -Zsanitizer=address
asan-address: export RUSTDOCFLAGS = -Zsanitizer=address
asan-address:
	cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu --workspace --all-targets --all-features

.PHONY: asan-memory
asan-memory: export RUSTFLAGS = -Zsanitizer=memory -Zsanitizer-memory-track-origins
asan-memory: export RUSTDOCFLAGS = -Zsanitizer=memory -Zsanitizer-memory-track-origins
asan-memory:
	cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu --workspace --all-targets --all-features

.PHONY: asan-leak
asan-leak: export RUSTFLAGS = -Zsanitizer=leak
asan-leak: export RUSTDOCFLAGS = -Zsanitizer=leak
asan-leak:
	cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu --workspace --all-targets --all-features

.PHONY: asan
asan: asan-address asan-memory asan-leak

# asan-address currently fails with `SIGILL` on functions with `extern "C"`
# so it is not included in memcheck until a solution is found
.PHONY: memcheck
memcheck: valgrind
