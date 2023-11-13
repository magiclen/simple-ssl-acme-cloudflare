Simple SSL with ACME and CloudFlare
====================

[![CI](https://github.com/magiclen/simple-ssl-acme-cloudflare/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/simple-ssl-acme-cloudflare/actions/workflows/ci.yml)

Simple SSL with ACME and CloudFlare is a tool to simply apply SSL certificates by using OpenSSL and ACME via CloudFlare DNS.

## Help

```
EXAMPLES:
simple-ssl-acme-cloudflare --cf-email xxx@example.com --cf-key xxxooo                      # Apply a SSL certificate and installs to the ssl folder in the current working directory
simple-ssl-acme-cloudflare --cf-email xxx@example.com --cf-key xxxooo -o /path/to/folder   # Apply a SSL certificate and installs to /path/to/folder

Usage: simple-ssl-acme-cloudflare [OPTIONS]

Options:
      --openssl-path <OPENSSL_PATH>  Specify the path of your compress executable binary file [default: openssl]
      --acme-path <ACME_PATH>        Specify the path of your ACME executable script file [default: acme.sh]
  -o, --output-path <OUTPUT_PATH>    Assign a destination of your installed certificate files. It should be a folder [default: ssl] [aliases: output]
  -k, --cf-key <CF_KEY>              Set the CloudFlare API key for your domain [env: CF_Key=]
  -e, --cf-email <CF_EMAIL>          Set the CloudFlare API email for your domain [env: CF_Email=]
      --force-csr-key                Force to regenerate a new CSR and a new key
      --force-dhparam                Force to regenerate a new dhparam
  -h, --help                         Print help
  -V, --version                      Print version
```

You need to put a **config.txt** file into the `OUTPUT_PATH` directory. That is used for **openssl**.

## License

[MIT](LICENSE)