Simple SSL with ACME and CloudFlare
====================

[![Build Status](https://travis-ci.org/magiclen/simple-ssl-acme-cloudflare.svg?branch=master)](https://travis-ci.org/magiclen/simple-ssl-acme-cloudflare)

Simple SSL with ACME and CloudFlare is a tool to simply apply SSL certificates by using OpenSSL and ACME via CloudFlare DNS.

## Help

```
EXAMPLES:
  simple-ssl-acme-cloudflare --cf-email xxx@example.com --cf-key xxxooo                    # Applies a SSL certificate and installs
to the ssl folder in the current working directory
  simple-ssl-acme-cloudflare --cf-email xxx@example.com --cf-key xxxooo -o /path/to/folder # Applies a SSL certificate and installs
to /path/to/folder

USAGE:
    simple-ssl-acme-cloudflare [FLAGS] [OPTIONS]

FLAGS:
        --force-csr-key    Forces to regenerate a new CSR and a new key.
        --force-dhparam    Forces to regenerate a new dhparam.
    -h, --help             Prints help information
    -V, --version          Prints version information

OPTIONS:
        --acme-path <ACME_PATH>          Specifies the path of your ACME executable script file. [default:
                                         /path/to/acme.sh]
    -e, --cf-email <CF_EMAIL>            Sets the CloudFlare API email for your domain.
    -k, --cf-key <CF_KEY>                Sets the CloudFlare API key for your domain.
        --openssl-path <OPENSSL_PATH>    Specifies the path of your openssl executable binary file. [default: openssl]
    -o, --output <OUTPUT_PATH>           Assigns a destination of your installed certificate files. It should be a folder.
                                         [default: /path/to/ssl]
```

You need to put a **config.txt** file into the `OUTPUT_PATH`. That is used for **openssl**.

## License

[MIT](LICENSE)