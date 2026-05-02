use anyhow::Result;
use clap::Parser;

use rustyarchive::cli::{Cli, Commands};
use rustyarchive::{archive, error, manifest, vault_format};

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let _ = std::mem::size_of::<error::RustyArchiveError>();
    let _ = manifest::MANIFEST_ARCHIVE_PATH;
    let _ = vault_format::FIXED_V1_HEADER_LENGTH;

    let cli = Cli::parse();

    match cli.command {
        Commands::Pack(args) => archive::pack(args),
        Commands::Unpack(args) => archive::unpack(args),
        Commands::Info(args) => archive::info(args),
    }
}
