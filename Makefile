LIB=libnss_dnsoverhttps.so
SO_VERSION=2
DESTDIR=/usr/lib

.PHONY: debug
debug: target/debug/$(LIB)
	cp $< .

.PHONY: release
release: target/release/$(LIB)
	cp $< .

.PHONY: install
install: release
	cp $(LIB) $(DESTDIR)/$(LIB).$(SO_VERSION)

target/debug/$(LIB): src/lib.rs
	cargo build

target/release/$(LIB): src/lib.rs
	cargo build --release
