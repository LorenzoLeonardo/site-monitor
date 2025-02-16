use std::path::PathBuf;

use async_trait::async_trait;
use oauth2::{HttpRequest, HttpResponse};

use crate::error::SiteMonitorResult;

use super::Interface;

#[derive(Clone)]
pub struct MockInterface {
    token_path: PathBuf,
    oauth2_perform_response: Option<SiteMonitorResult<HttpResponse>>,
    website_perform_response: Option<SiteMonitorResult<HttpResponse>>,
    profile_perform_response: Option<SiteMonitorResult<HttpResponse>>,
}

impl MockInterface {}

#[async_trait]
impl Interface for MockInterface {
    async fn oauth2_curl_perform(&self, _request: HttpRequest) -> SiteMonitorResult<HttpResponse> {
        self.oauth2_perform_response.as_ref().unwrap().clone()
    }
    async fn website_curl_perform(&self, _url: &str) -> SiteMonitorResult<HttpResponse> {
        self.website_perform_response.as_ref().unwrap().clone()
    }
    async fn profile_curl_perform(&self, _request: HttpRequest) -> SiteMonitorResult<HttpResponse> {
        self.profile_perform_response.as_ref().unwrap().clone()
    }
    fn get_token_path(&self) -> PathBuf {
        self.token_path.to_owned()
    }
}
