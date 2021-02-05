default: all

.PHONY: all
all: headers 

.PHONY: headers
headers: target/sawp/sawp.h target/sawp/modbus.h

target/sawp/sawp.h:
	RUSTUP_TOOLCHAIN=nightly cbindgen --config cbindgen.toml --crate sawp --output target/sawp/sawp.h -v --clean

target/sawp/modbus.h:
	cd sawp-modbus && \
	RUSTUP_TOOLCHAIN=nightly cbindgen --config cbindgen.toml --crate sawp-modbus --output ../target/sawp/modbus.h -v --clean

.PHONY: clean
clean:
	cargo clean
