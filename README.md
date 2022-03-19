Simple SSL with ACME and CloudFlare
====================

[![CI](https://github.com/magiclen/simple-ssl-acme-cloudflare/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/simple-ssl-acme-cloudflare/actions/workflows/ci.yml)

Simple SSL with ACME and CloudFlare is a tool to simply apply SSL certificates by using OpenSSL and ACME via CloudFlare DNS.

## Help

```
EXAMPLES:
simple-ssl-acme-cloudflare --cf-email xxx@example.com --cf-key xxxooo                    # Apply a SSL certificate and installs to the ssl folder in the current working directory
simple-ssl-acme-cloudflare --cf-email xxx@example.com --cf-key xxxooo -o /path/to/folder # Apply a SSL certificate and installs to /path/to/folder

USAGE:
    simple-ssl-acme-cloudflare [OPTIONS]

OPTIONS:
        --acme-path <ACME_PATH>          Specify the path of your ACME executable script file. [default: acme.sh]
    -e, --cf-email <CF_EMAIL>            Set the CloudFlare API email for your domain.
        --force-csr-key                  Force to regenerate a new CSR and a new key.
        --force-dhparam                  Force to regenerate a new dhparam.
    -h, --help                           Print help information
    -k, --cf-key <CF_KEY>                Set the CloudFlare API key for your domain.
    -o, --output <OUTPUT_PATH>           Assign a destination of your installed certificate files. It should be a folder. [default: ssl]
        --openssl-path <OPENSSL_PATH>    Specify the path of your openssl executable binary file. [default: openssl]
    -V, --version                        Print version information
```

You need to put a **config.txt** file into the `OUTPUT_PATH`. That is used for **openssl**.

## License

[MIT](LICENSE)