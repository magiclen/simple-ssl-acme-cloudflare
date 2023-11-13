mod cli;

use std::{fs, io, path::Path, process::Stdio};

use anyhow::{anyhow, Context};
use cli::*;
use execute::{command, command_args, Execute};

fn main() -> anyhow::Result<()> {
    let args = get_args();

    // check openssl and acme.sh
    {
        if command_args!(&args.openssl_path, "version", "-v")
            .execute_check_exit_status_code(0)
            .is_err()
        {
            return Err(anyhow!("Cannot find openssl."));
        }

        if command_args!(&args.acme_path, "--version").execute_check_exit_status_code(0).is_err() {
            return Err(anyhow!("Cannot find acme.sh."));
        }
    }

    // check output_path
    match args.output_path.metadata() {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(anyhow!("{:?} exists and it is not a directory.", args.output_path));
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(args.output_path.as_path())?;
        },
        Err(error) => return Err(error).with_context(|| anyhow!("{:?}", args.output_path)),
    }

    // create output paths
    let dhparam_path = args.output_path.join("dhparam");
    let csr_path = args.output_path.join("csr");
    let key_path = args.output_path.join("key");
    let crt_path = args.output_path.join("crt");
    let ca_path = args.output_path.join("ca");
    let chain_path = args.output_path.join("chain");
    let config_txt_path = args.output_path.join("config.txt");

    // handle dhparam
    {
        let generate_dhparam = match dhparam_path.metadata() {
            Ok(metadata) => {
                if metadata.is_dir() {
                    return Err(anyhow!("{dhparam_path:?} is a directory."));
                }

                args.force_dhparam
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error).with_context(|| anyhow!("{dhparam_path:?}")),
        };

        if generate_dhparam {
            println!("Generating dhparam, please wait for minutes...");

            let mut command = command_args!(
                &args.openssl_path,
                "dhparam",
                "-dsaparam",
                "-out",
                dhparam_path,
                "4096"
            );

            let output = command.execute_output().with_context(|| anyhow!("{command:?}"))?;

            if !output.status.success() {
                return Err(anyhow!("Cannot generate dhparam."));
            }
        }
    }

    // handle csr
    {
        let generate_csr = match csr_path.metadata() {
            Ok(metadata) => {
                if metadata.is_dir() {
                    return Err(anyhow!("{csr_path:?} is a directory."));
                }

                match key_path.metadata() {
                    Ok(metadata) => {
                        if metadata.is_dir() {
                            return Err(anyhow!("{key_path:?} is a directory."));
                        }

                        args.force_dhparam
                    },
                    Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                    Err(error) => return Err(error).with_context(|| anyhow!("{key_path:?}")),
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error).with_context(|| anyhow!("{csr_path:?}")),
        };

        if generate_csr {
            match config_txt_path.metadata() {
                Ok(metadata) => {
                    if !metadata.is_file() {
                        return Err(anyhow!("{config_txt_path:?} is not a file."));
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::write(
                        config_txt_path.as_path(),
                        "[req]
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
                    )
                    .with_context(|| anyhow!("{config_txt_path:?}"))?;

                    println!("Please make your config.txt by using a text editor. For example,");
                    println!("\tvim {config_txt_path:?}");

                    return Ok(());
                },
                Err(error) => {
                    return Err(error).with_context(|| anyhow!("{config_txt_path:?}"));
                },
            }

            let mut command = command_args!(
                &args.openssl_path,
                "req",
                "-config",
                config_txt_path,
                "-newkey",
                "rsa:4096",
                "-out",
                csr_path,
                "-nodes",
                "-keyout",
                key_path
            );

            let output = command.execute_output().with_context(|| anyhow!("{command:?}"))?;

            if !output.status.success() {
                return Err(anyhow!("Is Your config.txt correct?"));
            }
        }
    }

    println!("Applying your ssl certificate...");

    let domain = {
        let mut command1 = command_args!(&args.acme_path, "--showcsr", "--csr", csr_path.as_path());
        let mut command2 = command!("head -n 1");
        let mut command3 = command!("cut -d '=' -f 2");

        command3.stdout(Stdio::piped());

        let output = command1
            .execute_multiple_output(&mut [&mut command2, &mut command3])
            .with_context(|| anyhow!("{command1:?} | {command2:?} | {command3:?}"))?;

        if output.status.success() {
            unsafe { String::from_utf8_unchecked(output.stdout) }
        } else {
            return Err(anyhow!("Is Your CSR correct?"));
        }
    };

    let domain = domain.trim();

    // clear the domain directory
    {
        let domain_path = Path::new(args.acme_path.as_str()).parent().unwrap().join(domain);

        let _ = fs::remove_dir_all(domain_path);
    }

    // apply ssl
    {
        let mut command = command_args!(
            &args.acme_path,
            "--signcsr",
            "--csr",
            csr_path.as_path(),
            "--dns",
            "dns_cf",
            "--force"
        );
        command.env("CF_Key", args.cf_key).env("CF_Email", args.cf_email);

        let output = command.execute_output().with_context(|| anyhow!("{command:?}"))?;

        if !output.status.success() {
            return Err(anyhow!("Cannot apply your ssl certificate."));
        }
    }

    // install ssl
    {
        let mut command = command_args!(
            &args.acme_path,
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

        let output = command.execute_output().with_context(|| anyhow!("{command:?}"))?;

        if !output.status.success() {
            return Err(anyhow!("Cannot install your ssl certificate."));
        }
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
        args.output_path.canonicalize().unwrap().to_string_lossy()
    );

    Ok(())
}
