pub mod production;

use async_trait::async_trait;
use oauth2::{HttpRequest, HttpResponse};

use crate::error::SiteMonitorResult;

#[async_trait]
pub trait Interface: Clone + Send {
    async fn oauth2_curl_perform(&self, request: HttpRequest) -> SiteMonitorResult<HttpResponse>;
}
