#[macro_use]
extern crate lazy_static;
extern crate clap;
extern crate subprocess;
extern crate dirs;

use std::env;
use std::path::{Path, PathBuf};
use std::io::{ErrorKind, Write};
use std::fs::{self, File};

use subprocess::{Exec, ExitStatus, PopenError, NullFile};

use clap::{App, Arg};

// TODO -----Config START-----

const APP_NAME: &str = "Simple SSL with ACME and CloudFlare";
const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const CARGO_PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const DEFAULT_OPENSSL_PATH: &str = "openssl";

lazy_static! {
    static ref DEFAULT_ACME_PATH: PathBuf = {
        let home = dirs::home_dir().unwrap();
        Path::join(&Path::join(&home, Path::new(".acme.sh")), Path::new("acme.sh"))
    };
}

#[derive(Debug)]
pub struct ExePaths {
    pub openssl_path: String,
    pub acme_path: String,
}

impl ExePaths {
    pub fn new_default() -> ExePaths {
        ExePaths {
            openssl_path: String::from(DEFAULT_OPENSSL_PATH),
            acme_path: DEFAULT_ACME_PATH.to_str().unwrap().to_string(),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub paths: ExePaths,
    pub force_dhparam: bool,
    pub force_csr_key: bool,
    pub output_path: String,
    pub cf_key: Option<String>,
    pub cf_email: Option<String>,
}

impl Config {
    pub fn from_cli() -> Result<Config, String> {
        let arg0 = env::args().next().unwrap();
        let arg0 = Path::new(&arg0).file_stem().unwrap().to_str().unwrap();

        let cwd = env::current_dir().unwrap();

        let default_output_path = Path::join(&cwd, Path::new("ssl"));

        let examples = vec![
            "--cf-email xxx@example.com --cf-key xxxooo                    # Applies a SSL certificate and installs to the ssl folder in the current working directory",
            "--cf-email xxx@example.com --cf-key xxxooo -o /path/to/folder # Applies a SSL certificate and installs to /path/to/folder",
        ];

        let matches = App::new(APP_NAME)
            .version(CARGO_PKG_VERSION)
            .author(CARGO_PKG_AUTHORS)
            .about(format!("Simple SSL with ACME and CloudFlare is a tool to simply apply SSL certificates by using OpenSSL and ACME via CloudFlare DNS.\n\nEXAMPLES:\n{}", examples.iter()
                .map(|e| format!("  {} {}\n", arg0, e))
                .collect::<Vec<String>>()
                .concat()
            ).as_str()
            )
            .arg(Arg::with_name("OPENSSL_PATH")
                .global(true)
                .long("openssl-path")
                .help("Specifies the path of your openssl executable binary file.")
                .takes_value(true)
                .default_value(DEFAULT_OPENSSL_PATH)
            )
            .arg(Arg::with_name("ACME_PATH")
                .global(true)
                .long("acme-path")
                .help("Specifies the path of your ACME executable script file.")
                .takes_value(true)
                .default_value(DEFAULT_ACME_PATH.to_str().unwrap())
            )
            .arg(Arg::with_name("OUTPUT_PATH")
                .long("output")
                .short("o")
                .help("Assigns a destination of your installed certificate files. It should be a folder.")
                .takes_value(true)
                .default_value(default_output_path.to_str().unwrap())
            )
            .arg(Arg::with_name("CF_KEY")
                .long("cf-key")
                .short("k")
                .help("Sets the CloudFlare API key for your domain.")
                .takes_value(true)
            )
            .arg(Arg::with_name("CF_EMAIL")
                .long("cf-email")
                .short("e")
                .help("Sets the CloudFlare API email for your domain.")
                .takes_value(true)
            )
            .arg(Arg::with_name("FORCE_CSR_KEY")
                .long("force-csr-key")
                .help("Forces to regenerate a new CSR and a new key.")
            )
            .arg(Arg::with_name("FORCE_DHPARAM")
                .long("force-dhparam")
                .help("Forces to regenerate a new dhparam.")
            )
            .after_help("Enjoy it! https://magiclen.org")
            .get_matches();

        let openssl_path;
        let acme_path;

        {
            let get_executable_path = |name, default_path| {
                let path = matches.value_of(name).unwrap();

                if path.ne(default_path) {
                    let path = Path::new(path);

                    let path = match path.canonicalize() {
                        Ok(path) => {
                            path
                        }
                        Err(_) => {
                            return Err(format!("{} is incorrect.", name));
                        }
                    };

                    let path = path.to_str().unwrap();

                    Ok(String::from(path))
                } else {
                    Ok(String::from(path))
                }
            };

            openssl_path = get_executable_path("OPENSSL_PATH", DEFAULT_OPENSSL_PATH)?;
            acme_path = get_executable_path("ACME_PATH", DEFAULT_ACME_PATH.to_str().unwrap())?;
        }

        let output_path = matches.value_of("OUTPUT_PATH").unwrap().to_string();

        let cf_key = matches.value_of("CF_KEY").map(|s| s.to_string());

        let cf_email = matches.value_of("CF_EMAIL").map(|s| s.to_string());

        let force_csr_key = matches.is_present("FORCE_CSR_KEY");
        let force_dhparam = matches.is_present("FORCE_DHPARAM");

        let paths = ExePaths {
            openssl_path,
            acme_path,
        };

        Ok(Config {
            paths,
            output_path,
            force_csr_key,
            force_dhparam,
            cf_key,
            cf_email,
        })
    }
}

// TODO -----Config END-----

// TODO -----Process START-----

fn check_executable(cmd: &[&str]) -> Result<(), ()> {
    let process = Exec::cmd(cmd[0]).args(&cmd[1..]).stdout(NullFile {}).stderr(NullFile {});

    match execute_join(process) {
        Ok(es) => {
            if es == 0 {
                Ok(())
            } else {
                Err(())
            }
        }
        Err(_) => Err(())
    }
}

fn execute_three_string(cmd1: &[&str], cmd2: &[&str], cmd3: &[&str], cwd: &str) -> Result<String, String> {
    if let Err(error) = fs::create_dir_all(cwd) {
        return Err(error.to_string());
    }

    let process = { Exec::cmd(cmd1[0]).cwd(cwd).args(&cmd1[1..]) | Exec::cmd(cmd2[0]).cwd(cwd).args(&cmd2[1..]) | Exec::cmd(cmd3[0]).cwd(cwd).args(&cmd3[1..]) };

    match process.capture() {
        Ok(c) => {
            let es = match c.exit_status {
                ExitStatus::Exited(c) => c as i32,
                ExitStatus::Signaled(c) => c as i32,
                ExitStatus::Other(c) => c,
                _ => -1,
            };

            if es != 0 {
                return Err(format!("exit status code = {}", es));
            }

            Ok(c.stdout_str())
        }
        Err(error) => Err(error.to_string())
    }
}

fn execute_one_cf(cmd: &[&str], cwd: &str, cf_key: &str, cf_email: &str) -> Result<i32, String> {
    if let Err(error) = fs::create_dir_all(cwd) {
        return Err(error.to_string());
    }

    let process = Exec::cmd(cmd[0]).cwd(cwd).args(&cmd[1..]).env("CF_Key", cf_key).env("CF_Email", cf_email);

    match execute_join(process) {
        Ok(es) => {
            if es != 0 {
                return Err(format!("exit status code = {}", es));
            }
            Ok(es)
        }
        Err(error) => Err(error.to_string())
    }
}

fn execute_one(cmd: &[&str], cwd: &str) -> Result<i32, String> {
    if let Err(error) = fs::create_dir_all(cwd) {
        return Err(error.to_string());
    }

    let process = Exec::cmd(cmd[0]).cwd(cwd).args(&cmd[1..]);

    match execute_join(process) {
        Ok(es) => {
            if es != 0 {
                return Err(format!("exit status code = {}", es));
            }
            Ok(es)
        }
        Err(error) => Err(error.to_string())
    }
}

fn execute_join(process: Exec) -> Result<i32, PopenError> {
    match process.join() {
        Ok(es) => {
            match es {
                ExitStatus::Exited(c) => Ok(c as i32),
                ExitStatus::Signaled(c) => Ok(c as i32),
                ExitStatus::Other(c) => Ok(c),
                _ => Ok(-1),
            }
        }
        Err(error) => {
            Err(error)
        }
    }
}

// TODO -----Process END-----

pub fn run(config: Config) -> Result<i32, String> {
    let paths = config.paths;

    if let Err(_) = check_executable(&vec![paths.openssl_path.as_str(), "version", "-v"]) {
        return Err("Cannot find acme.sh".to_string());
    }

    if let Err(_) = check_executable(&vec![paths.acme_path.as_str(), "--version"]) {
        return Err("Cannot find acme.sh".to_string());
    }

    let cf_key = match config.cf_key {
        Some(s) => s,
        None => {
            match env::var("CF_Key") {
                Ok(s) => s,
                Err(_) => return Err("Cannot find CF_Key".to_string())
            }
        }
    };

    let cf_email = match config.cf_email {
        Some(s) => s,
        None => {
            match env::var("CF_Email") {
                Ok(s) => s,
                Err(_) => return Err("Cannot find CF_Email".to_string())
            }
        }
    };

    let output_path = Path::new(&config.output_path);

    let output_path = match output_path.canonicalize() {
        Ok(path) => {
            if path.is_file() {
                return Err(format!("{} exists and it is a file.", path.to_str().unwrap()));
            }
            path
        }
        Err(ref error) if error.kind() == ErrorKind::NotFound => {
            if let Err(_) = fs::create_dir_all(output_path) {
                return Err(format!("{} does not exist and cannot create it.", config.output_path));
            }
            match output_path.canonicalize() {
                Ok(p) => p,
                Err(err) => return Err(err.to_string())
            }
        }
        Err(_) => {
            return Err(format!("{} is incorrect.", config.output_path));
        }
    };

    let output_path_str = output_path.to_str().unwrap();

    let dhparam_path = Path::join(&output_path, "dhparam");
    let csr_path = Path::join(&output_path, "csr");
    let key_path = Path::join(&output_path, "key");
    let crt_path = Path::join(&output_path, "crt");
    let ca_path = Path::join(&output_path, "ca");
    let chain_path = Path::join(&output_path, "chain");
    let config_txt_path = Path::join(&output_path, "config.txt");

    {
        let generate_dhparam;

        if dhparam_path.exists() {
            if dhparam_path.is_dir() {
                return Err(format!("{} is a directory.", dhparam_path.to_str().unwrap()));
            }

            generate_dhparam = config.force_dhparam;
        } else {
            generate_dhparam = true;
        }

        if generate_dhparam {
            println!("Generating dhparam, please wait for minutes...");

            let cmd = vec![paths.openssl_path.as_str(), "dhparam", "-out", dhparam_path.to_str().unwrap(), "4096"];

            if let Err(_) = execute_one(&cmd, output_path_str) {
                return Err("Cannot generate dhparam.".to_string());
            }
        }
    }

    {
        let generate_csr;

        if csr_path.exists() && key_path.exists() {
            if csr_path.is_dir() {
                return Err(format!("{} is a directory.", csr_path.to_str().unwrap()));
            }

            if key_path.is_dir() {
                return Err(format!("{} is a directory.", key_path.to_str().unwrap()));
            }

            generate_csr = config.force_csr_key;
        } else {
            generate_csr = true;
        }

        if generate_csr {
            if config_txt_path.exists() {
                if config_txt_path.is_dir() {
                    return Err(format!("{} is a directory.", config_txt_path.to_str().unwrap()));
                }
            } else {
                let mut f = File::create(&config_txt_path).map_err(|e| e.to_string())?;

                f.write_all(br#"[req]
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
DNS.1 ="#).map_err(|e| e.to_string())?;

                println!("Please make your config.txt by using a text editor. For example,");
                println!("\tvim \"{}\"", config_txt_path.to_str().unwrap());
                return Ok(1);
            }

            let cmd = vec![paths.openssl_path.as_str(), "req", "-config", config_txt_path.to_str().unwrap(), "-newkey", "rsa:4096", "-out", csr_path.to_str().unwrap(), "-nodes", "-keyout", key_path.to_str().unwrap()];

            if let Err(_) = execute_one(&cmd, output_path_str) {
                return Err("Is Your config.txt correct?".to_string());
            }
        }
    }

    println!("Applying your ssl certificate...");

    let domain = {
        let cmd1 = vec![paths.acme_path.as_str(), "--showcsr", "--csr", csr_path.to_str().unwrap()];

        let cmd2 = vec!["head", "-n", "1"];

        let cmd3 = vec!["cut", "-d", "=", "-f", "2"];

        match execute_three_string(&cmd1, &cmd2, &cmd3, output_path_str) {
            Ok(s) => s,
            Err(_) => return Err("Is Your CSR correct?".to_string())
        }
    };

    let domain = domain.trim();

    let domain_path = Path::join(&Path::new(&paths.acme_path).parent().unwrap(), domain);

    {
        if let Err(_) = fs::remove_dir_all(&domain_path) {
            // do nothing
        }
    }

    {
        let cmd = vec![paths.acme_path.as_str(), "--signcsr", "--csr", csr_path.to_str().unwrap(), "--dns", "dns_cf", "--force"];

        if let Err(_) = execute_one_cf(&cmd, output_path_str, &cf_key, &cf_email) {
            return Err("Cannot apply your ssl certificate.".to_string());
        }
    }

    {
        let cmd = vec![paths.acme_path.as_str(), "--installcert", "--cert-file", crt_path.to_str().unwrap(), "--ca-file", ca_path.to_str().unwrap(), "--fullchain-file", chain_path.to_str().unwrap(), "-d", domain];

        if let Err(_) = execute_one(&cmd, output_path_str) {
            return Err("Cannot install your ssl certificate.".to_string());
        }
    }

    println!("Your new ssl certificate has been applied and installed successfully.");

    println!(r#"
-----Nginx-----
ssl_certificate "{0}/chain"
ssl_certificate_key "{0}/key"
ssl_dhparam "{0}/dhparam"

-----Apache-----
SSLCertificateFile "{0}/crt"
SSLCertificateKeyFile "{0}/key"
SSLCACertificateFile "{0}/ca""
SSLOpenSSLConfCmd DHParameters "{0}/dhparam""#, output_path.to_str().unwrap());

    Ok(0)
}