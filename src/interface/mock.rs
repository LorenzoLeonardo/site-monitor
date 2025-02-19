use std::{
    path::{Path, PathBuf},
    time::Duration,
};

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
    send_mail_response: Option<SiteMonitorResult<()>>,
}

impl MockInterface {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn set_oauth2_perform_response(&mut self, result: SiteMonitorResult<HttpResponse>) {
        self.oauth2_perform_response = Some(result);
    }

    pub fn set_website_perform_response(&mut self, result: SiteMonitorResult<HttpResponse>) {
        self.website_perform_response = Some(result);
    }

    pub fn set_profile_perform_response(&mut self, result: SiteMonitorResult<HttpResponse>) {
        self.profile_perform_response = Some(result);
    }

    pub fn set_send_mail_response(&mut self, result: SiteMonitorResult<()>) {
        self.send_mail_response = Some(result);
    }

    pub fn set_token_path(&mut self, path: &Path) {
        self.token_path = Some(path.to_path_buf());
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
        self.send_mail_response.as_ref().unwrap().to_owned()
    }

    fn get_config(&self) -> Config {
        Config {
            device_auth_url: DeviceAuthorizationUrl::new("https://devicecodeurl.com".into())
                .unwrap(),
            token_url: TokenUrl::new("https://tokenurl.com".into()).unwrap(),
            profile_url: ProfileUrl(Url::parse("https://profileurl.com").unwrap()),
            client_id: String::from("client-id-1234"),
            scopes: vec!["scope1".into(), "scope2".into()],
            smtp_server: String::from("smtp.server"),
            smtp_port: 123,
            recipient_email: String::from("test1234@gmail.com"),
            curl_connect_timeout: Duration::from_secs(60),
            smtp_connect_timeout: Duration::from_secs(60),
        }
    }
}
