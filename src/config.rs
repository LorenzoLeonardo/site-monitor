use std::{fs::File, io::BufReader, path::PathBuf, str::FromStr, time::Duration};

use oauth2::{DeviceAuthorizationUrl, TokenUrl};
use serde::{Deserialize, Serialize};

use crate::{error::SiteMonitorResult, profile::ProfileUrl};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Config {
    pub device_auth_url: DeviceAuthorizationUrl,
    pub token_url: TokenUrl,
    pub profile_url: ProfileUrl,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub recipient_email: String,
    pub curl_connect_timeout: Duration,
    pub smtp_connect_timeout: Duration,
}

impl Config {
    pub fn load() -> SiteMonitorResult<Self> {
        let file = File::open(PathBuf::from_str("config.json").unwrap())?;
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `User`.
        let config: Config = serde_json::from_reader(reader)?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use oauth2::{url::Url, DeviceAuthorizationUrl, TokenUrl};

    use crate::profile::ProfileUrl;

    use super::Config;
    #[test]
    fn test_load_config() {
        let config = Config::load().unwrap();
        assert_eq!(
            config,
            Config {
                device_auth_url: DeviceAuthorizationUrl::new(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".into()
                )
                .unwrap(),
                token_url: TokenUrl::new(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token".into()
                )
                .unwrap(),
                profile_url: ProfileUrl(
                    Url::parse("https://outlook.office.com/api/v2.0/me").unwrap()
                ),
                client_id: String::from("f7c886f5-00f6-4981-b000-b4d5ab0e5ef2"),
                scopes: vec![
                    "offline_access".into(),
                    "https://outlook.office.com/SMTP.Send".into(),
                    "https://outlook.office.com/User.Read".into()
                ],
                smtp_server: String::from("smtp.office365.com"),
                smtp_port: 587,
                recipient_email: String::from("enzotechcomputersolutions@gmail.com"),
                curl_connect_timeout: Duration::from_secs(60),
                smtp_connect_timeout: Duration::from_secs(60)
            }
        )
    }
}
