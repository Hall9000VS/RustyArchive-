use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "rustyarchive")]
#[command(version, about = "Pack files into encrypted .rav vaults")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Pack(PackArgs),
    Unpack(UnpackArgs),
    Info(InfoArgs),
}

#[derive(Debug, Args, Clone)]
pub struct PackArgs {
    pub input: PathBuf,
    #[arg(short, long)]
    pub output: PathBuf,
    #[arg(long)]
    pub overwrite: bool,
    #[arg(long)]
    pub no_progress: bool,
}

#[derive(Debug, Args, Clone)]
pub struct UnpackArgs {
    pub input: PathBuf,
    #[arg(short, long)]
    pub output: PathBuf,
    #[arg(long)]
    pub overwrite: bool,
    #[arg(long)]
    pub no_progress: bool,
}

#[derive(Debug, Args, Clone)]
pub struct InfoArgs {
    pub input: PathBuf,
}
