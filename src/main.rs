use anyhow::Result;
use clap::Parser;

use rustyarchive::archive;
use rustyarchive::cli::{Cli, Commands};

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pack(args) => archive::pack(args),
        Commands::Unpack(args) => archive::unpack(args),
        Commands::Info(args) => archive::info(args),
    }
}
