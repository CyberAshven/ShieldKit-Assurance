use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use schemars::schema_for;
use shieldkit_assurance_core::build_execution_plan;
use shieldkit_assurance_evidence::verify_bundle;
use shieldkit_assurance_schema::AssurancePack;

#[derive(Debug, Parser)]
#[command(
    name = "shieldkit-assure",
    version,
    about = "Claim-to-evidence protocol assurance"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Pack(PackCommand),
    Plan(PlanArgs),
    Schema(SchemaCommand),
    Evidence(EvidenceCommand),
}

#[derive(Debug, Args)]
struct PackCommand {
    #[command(subcommand)]
    command: PackSubcommand,
}

#[derive(Debug, Subcommand)]
enum PackSubcommand {
    Validate { pack: PathBuf },
}

#[derive(Debug, Args)]
struct PlanArgs {
    #[arg(long)]
    pack: PathBuf,
    #[arg(long)]
    suite: String,
}

#[derive(Debug, Args)]
struct SchemaCommand {
    #[command(subcommand)]
    command: SchemaSubcommand,
}

#[derive(Debug, Subcommand)]
enum SchemaSubcommand {
    Pack {
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
struct EvidenceCommand {
    #[command(subcommand)]
    command: EvidenceSubcommand,
}

#[derive(Debug, Subcommand)]
enum EvidenceSubcommand {
    Verify { bundle: PathBuf },
}

fn load_pack(path: &Path) -> Result<AssurancePack> {
    let bytes = fs::read(path).with_context(|| format!("read pack {}", path.display()))?;
    let pack: AssurancePack =
        serde_json::from_slice(&bytes).with_context(|| format!("parse pack {}", path.display()))?;
    pack.validate()
        .with_context(|| format!("validate pack {}", path.display()))?;
    Ok(pack)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create output directory {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary file in {}", parent.display()))?;
    temporary
        .write_all(bytes)
        .with_context(|| format!("write temporary schema for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("sync temporary schema for {}", path.display()))?;
    temporary
        .persist(path)
        .with_context(|| format!("atomically replace {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync output directory {}", parent.display()))?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Pack(PackCommand {
            command: PackSubcommand::Validate { pack },
        }) => {
            let value = load_pack(&pack)?;
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "status": "valid",
                    "packId": value.pack_id,
                    "packVersion": value.pack_version,
                    "claims": value.claims.len(),
                    "obligations": value.obligations.len(),
                    "tests": value.tests.len(),
                    "suites": value.suites.len()
                }))?
            );
        }
        Command::Plan(PlanArgs { pack, suite }) => {
            let value = load_pack(&pack)?;
            let plan = build_execution_plan(&value, &suite)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        Command::Schema(SchemaCommand {
            command: SchemaSubcommand::Pack { output },
        }) => {
            let mut encoded = serde_json::to_vec_pretty(&schema_for!(AssurancePack))?;
            encoded.push(b'\n');
            if let Some(output) = output {
                write_atomic(&output, &encoded)?;
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "status": "written",
                        "schema": "shieldkit-assurance-pack/v1",
                        "output": output
                    }))?
                );
            } else {
                std::io::stdout().write_all(&encoded)?;
            }
        }
        Command::Evidence(EvidenceCommand {
            command: EvidenceSubcommand::Verify { bundle },
        }) => {
            if !bundle.is_dir() {
                bail!("bundle is not a directory: {}", bundle.display());
            }
            let envelope = verify_bundle(&bundle)?;
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "status": "verified",
                    "runId": envelope.run_id,
                    "suiteId": envelope.manifest.suite_id,
                    "objects": envelope.manifest.objects.len() + 2
                }))?
            );
        }
    }
    Ok(())
}
