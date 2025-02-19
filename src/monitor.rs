use std::time::Duration;

use oauth2::http::StatusCode;

use crate::{auth, emailer, error::SiteMonitorError, interface::Interface, Stats};

pub async fn monitor_site<I: Interface + Clone + Send>(
    interface: I,
    site_to_monitor: &str,
) -> Result<(), SiteMonitorError> {
    let mut was_down = false;

    loop {
        let response = interface.website_curl_perform(site_to_monitor).await;
        match response {
            Ok(response) => {
                let status_code = response.status();
                let headers = response.headers();
                let body = if response.body().is_empty() {
                    None
                } else {
                    Some(response.body().clone())
                };

                log::debug!("[{}] {}", site_to_monitor, status_code);

                if (status_code != StatusCode::OK) && !was_down {
                    log::info!(
                        "[{}] {}, is down! Sending report...",
                        site_to_monitor,
                        status_code
                    );
                    let token = auth::request_token(interface.clone()).await?;
                    emailer::send_email(
                        &token,
                        interface.clone(),
                        site_to_monitor,
                        Some((&headers, status_code)),
                        body,
                        Stats::Down,
                        None,
                    )
                    .await
                    .map_or_else(
                        |err| {
                            log::error!("{err}");
                        },
                        |_| {
                            was_down = true;
                        },
                    );
                } else if (status_code == StatusCode::OK) && was_down {
                    log::info!(
                        "[{}] {}, is up! Sending report...",
                        site_to_monitor,
                        status_code
                    );
                    let token = auth::request_token(interface.clone()).await?;
                    emailer::send_email(
                        &token,
                        interface.clone(),
                        site_to_monitor,
                        Some((&headers, status_code)),
                        body,
                        Stats::Up,
                        None,
                    )
                    .await
                    .map_or_else(
                        |err| {
                            log::error!("{err}");
                        },
                        |_| {
                            was_down = false;
                        },
                    );
                }
            }
            Err(err) => {
                let error: SiteMonitorError = err.into();
                log::error!("[{}] {}", site_to_monitor, error);

                if !was_down {
                    let token = auth::request_token(interface.clone()).await?;
                    emailer::send_email(
                        &token,
                        interface.clone(),
                        site_to_monitor,
                        None,
                        None,
                        Stats::Down,
                        Some(error),
                    )
                    .await
                    .map_or_else(
                        |err| {
                            log::error!("{err}");
                        },
                        |_| {
                            was_down = true;
                        },
                    );
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
