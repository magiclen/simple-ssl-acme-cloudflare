use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser};
use concat_with::concat_line;
use terminal_size::terminal_size;

const APP_NAME: &str = "Simple SSL with ACME and CloudFlare";
const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const CARGO_PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

const AFTER_HELP: &str = "Enjoy it! https://magiclen.org";

const APP_ABOUT: &str = concat!(
    "Simple SSL with ACME and CloudFlare is a tool to simply apply SSL certificates by using \
     OpenSSL and ACME via CloudFlare DNS.\n\nEXAMPLES:\n",
    concat_line!(prefix "simple-ssl-acme-cloudflare ",
        "--cf-email xxx@example.com --cf-key xxxooo                      # Apply a SSL certificate and installs to the ssl folder in the current working directory",
        "--cf-email xxx@example.com --cf-key xxxooo -o /path/to/folder   # Apply a SSL certificate and installs to /path/to/folder",
    )
);

#[derive(Debug, Parser)]
#[command(name = APP_NAME)]
#[command(term_width = terminal_size().map(|(width, _)| width.0 as usize).unwrap_or(0))]
#[command(version = CARGO_PKG_VERSION)]
#[command(author = CARGO_PKG_AUTHORS)]
#[command(after_help = AFTER_HELP)]
pub struct CLIArgs {
    #[arg(long)]
    #[arg(default_value = "openssl")]
    #[arg(value_hint = clap::ValueHint::CommandName)]
    #[arg(help = "Specify the path of your compress executable binary file")]
    pub openssl_path: String,

    #[arg(long)]
    #[arg(default_value = "acme.sh")]
    #[arg(value_hint = clap::ValueHint::CommandName)]
    #[arg(help = "Specify the path of your ACME executable script file")]
    pub acme_path: String,

    #[arg(short, long, visible_alias = "output")]
    #[arg(default_value = "ssl")]
    #[arg(value_hint = clap::ValueHint::FilePath)]
    #[arg(help = "Assign a destination of your installed certificate files. It should be a folder")]
    pub output_path: PathBuf,

    #[arg(short = 'k', long, env = "CF_Key")]
    #[arg(help = "Set the CloudFlare API key for your domain")]
    pub cf_key: String,

    #[arg(short = 'e', long, env = "CF_Email")]
    #[arg(value_hint = clap::ValueHint::EmailAddress)]
    #[arg(help = "Set the CloudFlare API email for your domain")]
    pub cf_email: String,

    #[arg(long)]
    #[arg(help = "Force to regenerate a new CSR and a new key")]
    pub force_csr_key: bool,

    #[arg(long)]
    #[arg(help = "Force to regenerate a new dhparam")]
    pub force_dhparam: bool,
}

pub fn get_args() -> CLIArgs {
    let args = CLIArgs::command();

    let about = format!("{APP_NAME} {CARGO_PKG_VERSION}\n{CARGO_PKG_AUTHORS}\n{APP_ABOUT}");

    let args = args.about(about);

    let matches = args.get_matches();

    match CLIArgs::from_arg_matches(&matches) {
        Ok(args) => args,
        Err(err) => {
            err.exit();
        },
    }
}
