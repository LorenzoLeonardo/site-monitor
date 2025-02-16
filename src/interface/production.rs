use std::time::Duration;

use async_curl::CurlActor;
use async_trait::async_trait;
use curl_http_client::{dep::curl::easy::Easy2, Collector, HttpClient};
use oauth2::{HttpRequest, HttpResponse};

use crate::error::SiteMonitorResult;

use super::Interface;

#[derive(Clone)]
pub struct Production {
    actor: CurlActor<Collector>,
}

impl Production {
    pub fn new(actor: CurlActor<Collector>) -> Self {
        Self { actor }
    }
}

#[async_trait]
impl Interface for Production {
    async fn oauth2_curl_perform(&self, request: HttpRequest) -> SiteMonitorResult<HttpResponse> {
        log::debug!("Request Url: {}", request.uri());
        log::debug!("Request Header: {:?}", request.headers());
        log::debug!("Request Method: {}", request.method());
        log::debug!("Request Body: {}", String::from_utf8_lossy(request.body()));

        let response = HttpClient::new(Collector::RamAndHeaders(Vec::new(), Vec::new()))
            .request(request)?
            .nonblocking(self.actor.clone())
            .perform()
            .await?
            .map(|resp| {
                if let Some(resp) = resp {
                    resp
                } else {
                    Vec::new()
                }
            });

        log::debug!("Response Status: {}", response.status());
        log::debug!("Response Header: {:?}", response.headers());
        log::debug!(
            "Response Body: {}",
            String::from_utf8_lossy(response.body())
        );
        Ok(response)
    }

    async fn website_curl_perform(&self, url: &str) -> SiteMonitorResult<Easy2<Collector>> {
        let collector = Collector::RamAndHeaders(Vec::new(), Vec::new());
        let response = HttpClient::new(collector)
            .url(url)?
            .follow_location(true)?
            .connect_timeout(Duration::from_secs(30))?
            .timeout(Duration::from_secs(30))?
            .nobody(true)?
            .nonblocking(self.actor.clone())
            .send_request()
            .await?;
        Ok(response)
    }
}
