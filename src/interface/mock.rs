use std::path::PathBuf;

use async_trait::async_trait;
use mail_send::{mail_builder::MessageBuilder, Credentials};
use oauth2::{HttpRequest, HttpResponse};

use crate::error::SiteMonitorResult;

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
}
