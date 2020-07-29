all: ./target/x86_64-unknown-linux-musl/release/simple-ssl-acme-cloudflare

./target/x86_64-unknown-linux-musl/release/simple-ssl-acme-cloudflare: $(shell find . -type f -iname '*.rs' -o -name 'Cargo.toml' | sed 's/ /\\ /g')
	LZMA_API_STATIC=1 cargo build --release --target x86_64-unknown-linux-musl
	strip ./target/x86_64-unknown-linux-musl/release/simple-ssl-acme-cloudflare
	
install:
	$(MAKE)
	sudo cp ./target/x86_64-unknown-linux-musl/release/simple-ssl-acme-cloudflare /usr/local/bin/simple-ssl-acme-cloudflare
	sudo chown root: /usr/local/bin/simple-ssl-acme-cloudflare
	sudo chmod 0755 /usr/local/bin/simple-ssl-acme-cloudflare

uninstall:
	sudo rm /usr/local/bin/simple-ssl-acme-cloudflare

test:
	cargo test --verbose

clean:
	cargo clean
