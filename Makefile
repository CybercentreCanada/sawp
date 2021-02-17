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

$(eval CRATE_VERSION=$(shell (test -f Cargo.lock || cargo generate-lockfile) && cargo pkgid | cut -d# -f 2))
$(eval CRATE_VERSION_MINOR=$(shell echo ${CRATE_VERSION} | cut -d. -f 1-2))
$(eval CRATE_VERSION_MAJOR=$(shell echo ${CRATE_VERSION} | cut -d. -f 1))

FFI_PACKAGES := $(patsubst sawp-%/cbindgen.toml, %, $(wildcard sawp-*/cbindgen.toml))
FFI_HEADERS := target/sawp/sawp.h $(patsubst %, target/sawp/%.h, ${FFI_PACKAGES})
FFI_OBJECTS_RELEASE := $(patsubst %.so, %.so.${CRATE_VERSION}, \
	target/release/libsawp.so $(patsubst %, target/release/libsawp_%.so, ${FFI_PACKAGES}))
FFI_OBJECTS_DEBUG := target/debug/libsawp.so $(patsubst %, target/debug/libsawp_%.so, ${FFI_PACKAGES})

# Source pattern to detect file changes and cache the build.
# Any source file change in the workspace should trigger a rebuild.
SOURCES := $(shell find . sawp-* -type f \( -name "*.rs" -or -name "cbindgen.toml" -or -name "Cargo.toml" \) )

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
	cargo build --features ffi --release

target/debug/libsawp.so: ${SOURCES}
	cargo build --features ffi --features verbose

target/release/libsawp.so: ${SOURCES}
	cargo build --features ffi --release

target/release/%.so.${CRATE_VERSION}: target/release/%.so
	cp $^ $^.${CRATE_VERSION}

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
	cp target/sawp/*.h target/_temp/include/sawp
	cp -d target/release/*.so.* target/_temp/lib64
	tar -czvf target/rpmbuild/SOURCES/sawp-${CRATE_VERSION}.tar.gz target/_temp --transform 'flags=r;s#^target/_temp#sawp-${CRATE_VERSION}#'
