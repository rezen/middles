use clap::Parser;
use middles::{App, config::Config};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// TOML configuration (omitting this uses safe local defaults)
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Validate configuration and exit
    #[arg(long)]
    check: bool,
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
