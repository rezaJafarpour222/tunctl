use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "proxyctl",
    version,
    about = "Userspace TCP proxy through a SOCKS5 server"
)]
pub struct Config {
    /// SOCKS5 server address, for example 127.0.0.1:1080
    #[arg(long)]
    pub socks5: String,

    /// SOCKS5 username
    #[arg(long)]
    pub username: String,

    /// SOCKS5 password
    #[arg(long)]
    pub password: String,

    /// Install Linux routing policy automatically
    #[arg(long)]
    pub auto_route: bool,
}

impl Config {
    pub fn from_args() -> Result<Self, String> {
        let config = Self::parse();

        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.socks5.is_empty() {
            return Err("SOCKS5 address cannot be empty".to_string());
        }

        if self.username.is_empty() {
            return Err("SOCKS5 username cannot be empty".to_string());
        }

        if self.password.is_empty() {
            return Err("SOCKS5 password cannot be empty".to_string());
        }

        Ok(())
    }
}
