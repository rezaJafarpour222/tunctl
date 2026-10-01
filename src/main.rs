use tun::{config, stack::engine};

#[cfg(not(target_os = "linux"))]
compile_error!("proxyctl currently supports Linux only");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::Config::from_args()?;

    engine::run(config).await?;

    Ok(())
}
