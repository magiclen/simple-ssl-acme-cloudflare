all: ./target/release/simple-ssl-acme-cloudflare

./target/release/simple-ssl-acme-cloudflare: $(shell find . -type f -iname '*.rs' -o -name 'Cargo.toml' | sed 's/ /\\ /g')
	cargo build --release
	strip ./target/release/simple-ssl-acme-cloudflare
	
install:
	$(MAKE)
	sudo cp ./target/release/simple-ssl-acme-cloudflare /usr/local/bin/simple-ssl-acme-cloudflare
	sudo chown root. /usr/local/bin/simple-ssl-acme-cloudflare
	sudo chmod 0755 /usr/local/bin/simple-ssl-acme-cloudflare
	
test:
	cargo test --verbose

clean:
	cargo clean
