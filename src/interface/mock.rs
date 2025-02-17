use std::{path::PathBuf, time::Duration};

use async_trait::async_trait;
use mail_send::{mail_builder::MessageBuilder, Credentials};
use oauth2::{url::Url, DeviceAuthorizationUrl, HttpRequest, HttpResponse, TokenUrl};

use crate::{config::Config, error::SiteMonitorResult, profile::ProfileUrl};

use super::Interface;

#[derive(Clone, Default)]
pub struct MockInterface {
    token_path: Option<PathBuf>,
    oauth2_perform_response: Option<SiteMonitorResult<HttpResponse>>,
    website_perform_response: Option<SiteMonitorResult<HttpResponse>>,
    profile_perform_response: Option<SiteMonitorResult<HttpResponse>>,
}

impl MockInterface {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
    #[allow(dead_code)]
    pub fn set_oauth2_perform_response(&mut self, result: SiteMonitorResult<HttpResponse>) {
        self.oauth2_perform_response = Some(result);
    }
    #[allow(dead_code)]
    pub fn set_website_perform_response(&mut self, result: SiteMonitorResult<HttpResponse>) {
        self.website_perform_response = Some(result);
    }

    pub fn set_profile_perform_response(&mut self, result: SiteMonitorResult<HttpResponse>) {
        self.profile_perform_response = Some(result);
    }
}

#[async_trait]
impl Interface for MockInterface {
    async fn oauth2_curl_perform(&self, _request: HttpRequest) -> SiteMonitorResult<HttpResponse> {
        self.oauth2_perform_response.as_ref().unwrap().to_owned()
    }
    async fn website_curl_perform(&self, _url: &str) -> SiteMonitorResult<HttpResponse> {
        self.website_perform_response.as_ref().unwrap().to_owned()
    }
    async fn profile_curl_perform(&self, _request: HttpRequest) -> SiteMonitorResult<HttpResponse> {
        self.profile_perform_response.as_ref().unwrap().to_owned()
    }
    fn get_token_path(&self) -> PathBuf {
        self.token_path.as_ref().unwrap().to_owned()
    }
    async fn send_email<'x>(
        &self,
        _credentials: Credentials<String>,
        _message: MessageBuilder<'x>,
    ) -> SiteMonitorResult<()> {
        Ok(())
    }

    fn get_config(&self) -> Config {
        Config {
            device_auth_url: DeviceAuthorizationUrl::new(
                "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".into(),
            )
            .unwrap(),
            token_url: TokenUrl::new(
                "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
            )
            .unwrap(),
            profile_url: ProfileUrl(Url::parse("https://outlook.office.com/api/v2.0/me").unwrap()),
            client_id: String::from("f7c886f5-00f6-4981-b000-b4d5ab0e5ef2"),
            scopes: vec![
                "offline_access".into(),
                "https://outlook.office.com/SMTP.Send".into(),
                "https://outlook.office.com/User.Read".into(),
            ],
            smtp_server: String::from("smtp.office365.com"),
            smtp_port: 587,
            recipient_email: String::from("enzotechcomputersolutions@gmail.com"),
            curl_connect_timeout: Duration::from_secs(60),
            smtp_connect_timeout: Duration::from_secs(60),
        }
    }
}
