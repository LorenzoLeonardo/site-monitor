use std::{path::PathBuf, time::Duration};

use async_curl::CurlActor;
use async_trait::async_trait;
use curl_http_client::{Collector, HttpClient};
use directories::UserDirs;
use oauth2::{HttpRequest, HttpResponse};

use crate::error::SiteMonitorResult;

use super::Interface;

#[derive(Clone)]
pub struct Production {
    actor: CurlActor<Collector>,
    token_path: PathBuf,
}

impl Production {
    pub fn new(actor: CurlActor<Collector>) -> Self {
        let directory = UserDirs::new().unwrap();
        let mut directory = directory.home_dir().to_owned();

        directory = directory.join("token");

        Self {
            actor,
            token_path: directory,
        }
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

    async fn website_curl_perform(&self, url: &str) -> SiteMonitorResult<HttpResponse> {
        let collector = Collector::RamAndHeaders(Vec::new(), Vec::new());
        let response = HttpClient::new(collector)
            .url(url)?
            .follow_location(true)?
            .connect_timeout(Duration::from_secs(30))?
            .timeout(Duration::from_secs(30))?
            .nobody(true)?
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
        Ok(response)
    }

    async fn profile_curl_perform(&self, request: HttpRequest) -> SiteMonitorResult<HttpResponse> {
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

    fn get_token_path(&self) -> PathBuf {
        self.token_path.to_owned()
    }
}
