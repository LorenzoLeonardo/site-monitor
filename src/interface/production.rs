use std::path::PathBuf;

use async_trait::async_trait;
use curl_http_client::{dep::async_curl::CurlActor, Collector, HttpClient};
use directories::UserDirs;
use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::{HttpRequest, HttpResponse};

use crate::{config::Config, error::SiteMonitorResult};

use super::Interface;

#[derive(Clone)]
pub struct Production {
    actor: CurlActor<Collector>,
    token_path: PathBuf,
    config: Config,
}

impl Production {
    pub fn new(actor: CurlActor<Collector>, config: Config) -> Self {
        let directory = UserDirs::new().unwrap();
        let mut directory = directory.home_dir().to_owned();

        directory = directory.join("token");

        Self {
            actor,
            token_path: directory,
            config,
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
            .connect_timeout(self.config.curl_connect_timeout)?
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
            .connect_timeout(self.config.curl_connect_timeout)?
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
            .connect_timeout(self.config.curl_connect_timeout)?
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

    async fn send_email<'x>(
        &self,
        credentials: Credentials<String>,
        message: MessageBuilder<'x>,
    ) -> SiteMonitorResult<()> {
        let mut result =
            SmtpClientBuilder::new(self.config.smtp_server.clone(), self.config.smtp_port)
                .implicit_tls(false)
                .credentials(credentials)
                .timeout(self.config.smtp_connect_timeout)
                .connect()
                .await?;

        result.send(message).await?;
        Ok(())
    }

    fn get_config(&self) -> Config {
        self.config.clone()
    }
}
