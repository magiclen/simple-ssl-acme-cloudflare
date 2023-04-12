use std::{
    borrow::Cow,
    env,
    error::Error,
    fs::{self, File},
    io::Write,
    path::Path,
    process::{self, Stdio},
};

use clap::{Arg, Command};
use concat_with::concat_line;
use execute::{command, command_args, Execute};
use path_absolutize::Absolutize;
use terminal_size::terminal_size;

const APP_NAME: &str = "Simple SSL with ACME and CloudFlare";
const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const CARGO_PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

const DEFAULT_OPENSSL_PATH: &str = "openssl";
const DEFAULT_ACME_PATH: &str = "acme.sh";
const DEFAULT_OUTPUT_PATH: &str = "ssl";

fn main() -> Result<(), Box<dyn Error>> {
    let matches = Command::new(APP_NAME)
        .term_width(terminal_size().map(|(width, _)| width.0 as usize).unwrap_or(0))
        .version(CARGO_PKG_VERSION)
        .author(CARGO_PKG_AUTHORS)
        .about(concat!("Simple SSL with ACME and CloudFlare is a tool to simply apply SSL certificates by using OpenSSL and ACME via CloudFlare DNS.\n\nEXAMPLES:\n", concat_line!(prefix "simple-ssl-acme-cloudflare ",
                "--cf-email xxx@example.com --cf-key xxxooo                    # Apply a SSL certificate and installs to the ssl folder in the current working directory",
                "--cf-email xxx@example.com --cf-key xxxooo -o /path/to/folder # Apply a SSL certificate and installs to /path/to/folder",
            )))
        .arg(Arg::new("OPENSSL_PATH")
            .global(true)
            .long("openssl-path")
            .help("Specify the path of your openssl executable binary file.")
            .takes_value(true)
            .default_value(DEFAULT_OPENSSL_PATH)
        )
        .arg(Arg::new("ACME_PATH")
            .global(true)
            .long("acme-path")
            .help("Specify the path of your ACME executable script file.")
            .takes_value(true)
            .default_value(DEFAULT_ACME_PATH)
        )
        .arg(Arg::new("OUTPUT_PATH")
            .long("output")
            .short('o')
            .help("Assign a destination of your installed certificate files. It should be a folder.")
            .takes_value(true)
            .default_value(DEFAULT_OUTPUT_PATH)
        )
        .arg(Arg::new("CF_KEY")
            .long("cf-key")
            .short('k')
            .help("Set the CloudFlare API key for your domain.")
            .takes_value(true)
        )
        .arg(Arg::new("CF_EMAIL")
            .long("cf-email")
            .short('e')
            .help("Set the CloudFlare API email for your domain.")
            .takes_value(true)
        )
        .arg(Arg::new("FORCE_CSR_KEY")
            .long("force-csr-key")
            .help("Force to regenerate a new CSR and a new key.")
        )
        .arg(Arg::new("FORCE_DHPARAM")
            .long("force-dhparam")
            .help("Force to regenerate a new dhparam.")
        )
        .after_help("Enjoy it! https://magiclen.org")
        .get_matches();

    let openssl_path = matches.value_of("OPENSSL_PATH").unwrap();
    let acme_path = matches.value_of("ACME_PATH").unwrap();

    let output_path = matches.value_of("OUTPUT_PATH").unwrap();

    let cf_key = matches.value_of("CF_KEY");
    let cf_email = matches.value_of("CF_EMAIL");

    let force_csr_key = matches.is_present("FORCE_CSR_KEY");
    let force_dhparam = matches.is_present("FORCE_DHPARAM");

    if command_args!(openssl_path, "version", "-v").execute_check_exit_status_code(0).is_err() {
        return Err("Cannot find openssl.".into());
    }

    if command_args!(acme_path, "--version").execute_check_exit_status_code(0).is_err() {
        return Err("Cannot find acme.sh.".into());
    }

    let cf_key = match cf_key {
        Some(s) => Cow::from(s),
        None => Cow::from(env::var("CF_Key").map_err(|_| "Cannot find CF_Key.")?),
    };

    let cf_email = match cf_email {
        Some(s) => Cow::from(s),
        None => Cow::from(env::var("CF_Email").map_err(|_| "Cannot find CF_Email.")?),
    };

    let output_path = Path::new(output_path);

    match output_path.metadata() {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(format!(
                    "{} exists and it is not a directory.",
                    output_path.absolutize()?.to_string_lossy()
                )
                .into());
            }
        },
        Err(_) => {
            fs::create_dir_all(output_path)?;
        },
    }

    let dhparam_path = Path::join(output_path, "dhparam");
    let csr_path = Path::join(output_path, "csr");
    let key_path = Path::join(output_path, "key");
    let crt_path = Path::join(output_path, "crt");
    let ca_path = Path::join(output_path, "ca");
    let chain_path = Path::join(output_path, "chain");
    let config_txt_path = Path::join(output_path, "config.txt");

    let generate_dhparam = if dhparam_path.exists() {
        if !dhparam_path.is_file() {
            return Err(
                format!("{} is not a file.", dhparam_path.absolutize()?.to_string_lossy()).into()
            );
        }

        force_dhparam
    } else {
        true
    };

    if generate_dhparam {
        println!("Generating dhparam, please wait for minutes...");

        let mut command =
            command_args!(openssl_path, "dhparam", "-dsaparam", "-out", dhparam_path, "4096");

        let output = command.execute_output()?;

        match output.status.code() {
            Some(exit_code) => {
                if exit_code != 0 {
                    return Err("Cannot generate dhparam.".into());
                }
            },
            None => {
                process::exit(1);
            },
        }
    }

    let generate_csr = if csr_path.is_file() && key_path.is_file() { force_csr_key } else { true };

    if generate_csr {
        match config_txt_path.metadata() {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(format!(
                        "{} is a directory.",
                        config_txt_path.absolutize()?.to_string_lossy()
                    )
                    .into());
                }
            },
            Err(_) => {
                let mut f = File::create(config_txt_path.as_path())?;

                f.write_all(
                    b"[req]
default_bits       = 4096
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[dn]
# *Common Name (e.g. server FQDN or YOUR name)
CN =

# Locality Name (e.g. YOUR city name)
L  =

# State or Province Name
ST =

# Organization Name (e.g. YOUR company name)
O  =

# Organizational Unit Name (e.g. YOUR section name)
OU =

# Country Name (ISO 3166-1 alpha-2 code)
C  =

# Email Address
emailAddress    =

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 =",
                )?;

                println!("Please make your config.txt by using a text editor. For example,");
                println!("\tvim \"{}\"", config_txt_path.to_str().unwrap());

                return Ok(());
            },
        }

        let mut command = command_args!(
            openssl_path,
            "req",
            "-config",
            config_txt_path,
            "-newkey",
            "rsa:4096",
            "-out",
            csr_path.as_path(),
            "-nodes",
            "-keyout",
            key_path
        );

        let output = command.execute_output()?;

        match output.status.code() {
            Some(exit_code) => {
                if exit_code != 0 {
                    return Err("Is Your config.txt correct?".into());
                }
            },
            None => {
                process::exit(1);
            },
        }
    }

    println!("Applying your ssl certificate...");

    let domain = {
        let mut command1 = command_args!(acme_path, "--showcsr", "--csr", csr_path.as_path());
        let mut command2 = command!("head -n 1");
        let mut command3 = command!("cut -d '=' -f 2");

        command3.stdout(Stdio::piped());

        let output = command1.execute_multiple_output(&mut [&mut command2, &mut command3])?;

        match output.status.code() {
            Some(exit_code) => {
                if exit_code != 0 {
                    return Err("Is Your CSR correct?".into());
                } else {
                    unsafe { String::from_utf8_unchecked(output.stdout) }
                }
            },
            None => {
                process::exit(1);
            },
        }
    };

    let domain = domain.trim();

    let domain_path = Path::new(acme_path).parent().unwrap().join(domain);

    if fs::remove_dir_all(domain_path).is_err() {
        // do nothing
    }

    let mut command = command_args!(
        acme_path,
        "--signcsr",
        "--csr",
        csr_path.as_path(),
        "--dns",
        "dns_cf",
        "--force"
    );
    command.env("CF_Key", cf_key.as_ref()).env("CF_Email", cf_email.as_ref());

    let output = command.execute_output()?;

    match output.status.code() {
        Some(exit_code) => {
            if exit_code != 0 {
                return Err("Cannot apply your ssl certificate.".into());
            }
        },
        None => {
            process::exit(1);
        },
    }

    let mut command = command_args!(
        acme_path,
        "--installcert",
        "--cert-file",
        crt_path,
        "--ca-file",
        ca_path,
        "--fullchain-file",
        chain_path,
        "-d",
        domain
    );

    let output = command.execute_output()?;

    match output.status.code() {
        Some(exit_code) => {
            if exit_code != 0 {
                return Err("Cannot install your ssl certificate.".into());
            }
        },
        None => {
            process::exit(1);
        },
    }

    println!("Your new ssl certificate has been applied and installed successfully.");

    println!(
        r#"
-----Nginx-----
ssl_certificate "{0}/chain"
ssl_certificate_key "{0}/key"
ssl_dhparam "{0}/dhparam"

-----Apache-----
SSLCertificateFile "{0}/chain"
SSLCertificateKeyFile "{0}/key"
SSLOpenSSLConfCmd DHParameters "{0}/dhparam""#,
        output_path.absolutize()?.to_string_lossy()
    );

    Ok(())
}
