pub mod production;

use std::path::PathBuf;

use async_trait::async_trait;
use curl_http_client::{dep::curl::easy::Easy2, Collector};
use oauth2::{HttpRequest, HttpResponse};

use crate::error::SiteMonitorResult;

#[async_trait]
pub trait Interface: Clone + Send {
    async fn oauth2_curl_perform(&self, request: HttpRequest) -> SiteMonitorResult<HttpResponse>;
    async fn website_curl_perform(&self, url: &str) -> SiteMonitorResult<Easy2<Collector>>;
    async fn profile_curl_perform(&self, request: HttpRequest) -> SiteMonitorResult<HttpResponse>;
    fn get_token_path(&self) -> PathBuf;
}
