use clap::{Parser, Subcommand};
use middles::{
    App,
    config::Config,
    osv_sync,
    setup::{self, Client},
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// TOML configuration (omitting this uses safe local defaults)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    /// Validate configuration and exit
    #[arg(long)]
    check: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Point local package managers (npm, pnpm, Yarn, Bun, pip, uv, Composer, Bundler, Homebrew, APT) at this proxy
    Configure(Configure),
    /// Import OSV dump archives into the local advisory mirror
    OsvSync(OsvSync),
}

#[derive(clap::Args)]
struct OsvSync {
    /// SQLite mirror path (default: cache.path from configuration)
    #[arg(long)]
    database: Option<PathBuf>,
    /// Ecosystems to import [npm, PyPI, Packagist, RubyGems, Debian, Ubuntu]
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    ecosystems: Vec<String>,
    /// Read <ecosystem>.zip files from a directory instead of downloading them
    #[arg(long)]
    source_dir: Option<PathBuf>,
}

#[derive(clap::Args)]
struct Configure {
    /// Proxy base URL for clients (default: public_url from the configuration)
    #[arg(long)]
    url: Option<String>,
    /// Configure only these clients, comma-separated [possible: npm (also pnpm, yarn1), yarn, bun, pip, uv, composer, bundler, homebrew, apt]
    #[arg(long, value_delimiter = ',', value_parser = Client::parse)]
    only: Vec<Client>,
    /// Leave these clients alone, comma-separated
    #[arg(long, value_delimiter = ',', value_parser = Client::parse)]
    skip: Vec<Client>,
    /// Shell profile that receives environment variables (default: derived from $SHELL)
    #[arg(long)]
    profile: Option<PathBuf>,
    /// Show the planned changes without writing anything
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "middles=info,tower_http=info".into()),
        )
        .init();
    let args = Args::parse();
    let config: Config = match args.config {
        Some(path) => toml::from_str(&std::fs::read_to_string(path)?)?,
        None => Config::default(),
    };
    config.validate()?;
    match args.command {
        Some(Command::Configure(options)) => return configure(&config, options),
        Some(Command::OsvSync(options)) => {
            let ecosystems = if options.ecosystems.is_empty() {
                osv_sync::DEFAULT_ECOSYSTEMS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect()
            } else {
                options.ecosystems
            };
            let database = options.database.as_deref().unwrap_or(&config.cache.path);
            for imported in
                osv_sync::sync(database, &ecosystems, options.source_dir.as_deref()).await?
            {
                println!(
                    "{}: imported {} package advisories",
                    imported.ecosystem, imported.records
                );
            }
            return Ok(());
        }
        None => {}
    }
    if args.check {
        println!("Configuration valid");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(listen = %listener.local_addr()?, public_url = %config.public_url, "middles listening");
    let app = App::new(config).await?;
    axum::serve(listener, app.router())
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

fn configure(config: &Config, options: Configure) -> anyhow::Result<()> {
    let env = setup::Environment::detect(options.profile)?;
    let url = setup::base_url(options.url.as_deref().unwrap_or(&config.public_url))?;
    let mut changes = setup::plan(config, &url, &options.only, &options.skip, &env)?;
    if !options.dry_run {
        setup::apply(&mut changes)?;
    }
    setup::report(
        &mut std::io::stdout().lock(),
        &changes,
        &env,
        options.dry_run,
    )?;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
