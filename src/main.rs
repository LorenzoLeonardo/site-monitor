mod auth;
mod config;
mod emailer;
mod error;
mod interface;
mod profile;
mod watcher;

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use async_curl::CurlActor;
use chrono::{FixedOffset, Local};
use config::Config;
use emailer::Emailer;
use error::{ErrorCodes, SiteMonitorError, SiteMonitorResult};

use interface::Interface;
use log::LevelFilter;
use oauth2::http::{HeaderMap, StatusCode};
use oauth2::{AccessToken, Scope};
use tokio::select;
use tokio::sync::mpsc::channel;

use interface::production::Production;
use profile::get_sender_profile;
use watcher::{watch_file, WatcherAction};

#[derive(Debug, strum_macros::Display)]
enum Stats {
    Up,
    Down,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let log_level = if args.len() <= 1 {
        "info"
    } else {
        args[1].as_str()
    };
    let log_level = LevelFilter::from_str(log_level)
        .expect("Log level input must be: off, error, warn, info, debug, trace");
    init_logger(log_level);
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    log::info!("{name} has started v{version}...");
    log::info!("Log {:?}", log_level);

    let config = Config::load().unwrap();
    let interface = Production::new(CurlActor::new(), config);

    let _ = request_token(interface.clone()).await?;
    let (tx, mut rx) = channel(1);
    let _ = watch_file(tx, PathBuf::from_str("websites.txt")?).await;

    let mut hash_map_task = HashMap::new();

    loop {
        select! {
            Some(msg) = rx.recv() => {
                match msg {
                    WatcherAction::Add(sites) => {
                        for site in sites {
                            let site_inner = site.clone();
                            let inner_interface = interface.clone();
                            let handle = tokio::spawn(async move {
                                if let Err(err) = monitor_site(inner_interface, site_inner.as_str()).await {
                                    log::error!("[{}] {}", site_inner.as_str(), err.to_string());
                                }
                            });
                            log::info!("[{site}] was just added into monitoring.");
                            hash_map_task.insert(site, handle);
                         }
                    },
                    WatcherAction::Remove(sites) => {
                        for site in sites {
                            if let Some(value) = hash_map_task.remove(&site) {
                                value.abort();
                                log::info!("[{site}] was just removed from monitoring.");
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn monitor_site<I: Interface + Clone + Send>(
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
                    let token = request_token(interface.clone()).await?;
                    send_email(
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
                    let token = request_token(interface.clone()).await?;
                    send_email(
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
                    let token = request_token(interface.clone()).await?;
                    send_email(
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

async fn request_token<I: Interface + Clone + Send>(
    interface: I,
) -> SiteMonitorResult<AccessToken> {
    let config = interface.get_config();
    let scopes: Vec<Scope> = config
        .scopes
        .iter()
        .map(|s| Scope::new(s.to_string()))
        .collect();

    loop {
        let result = auth::device_code_flow(
            &config.client_id,
            None,
            config.device_auth_url.to_owned(),
            config.token_url.to_owned(),
            scopes.to_owned(),
            interface.to_owned(),
        )
        .await;
        match result {
            Ok(result) => return Ok(result),
            Err(err) => {
                if err.error_code == ErrorCodes::InvalidGrant
                    || err.error_code == ErrorCodes::NoToken
                    || err.error_code == ErrorCodes::ExpiredToken
                {
                    log::error!("{err} Please login again!");
                } else {
                    return Err(err);
                }
            }
        }
    }
}

async fn send_email<I: Interface + Clone>(
    token: &AccessToken,
    interface: I,
    url: &str,
    header_status: Option<(&HeaderMap, StatusCode)>,
    html: Option<Vec<u8>>,
    stats: Stats,
    error: Option<SiteMonitorError>,
) -> SiteMonitorResult<()> {
    let config = interface.get_config();
    let (_sender_name, sender_email) =
        get_sender_profile(&token, &config.profile_url, interface.clone()).await?;

    let report = format_email_report(url, header_status, stats, error);

    Emailer::new(interface)
        .set_sender("Enzo Tech Web Monitor".to_string(), sender_email.0)
        .add_recipient(
            "Lorenzo Leonardo".into(),
            "enzotechcomputersolutions@gmail.com".into(),
        )
        .send_email(
            token,
            "Enzo Tech Web Monitoring Report",
            report.as_str(),
            html,
        )
        .await;
    Ok(())
}

fn format_email_report(
    url: &str,
    header_status: Option<(&HeaderMap, StatusCode)>,
    stats: Stats,
    error: Option<SiteMonitorError>,
) -> String {
    let local_dt = Local::now();
    let offset_in_seconds = local_dt.offset().local_minus_utc();

    if let Some(error) = error {
        format!(
            "{url} is {stats} at {}\r\n\r\nCode: {}\r\nDescription: {}",
            local_dt
                .with_timezone(&FixedOffset::east_opt(offset_in_seconds).unwrap())
                .format("%a, %d %b %Y %H:%M:%S (GMT%:z)"),
            error.error_code,
            error.error_code_desc
        )
    } else {
        if let Some(header_status) = header_status {
            let status = header_status.1;
            let header = header_status
                .0
                .iter()
                .map(|(key, value)| format!("{}: {}", key.as_str(), value.to_str().unwrap_or("")))
                .collect::<Vec<String>>()
                .join("\r\n");
            format!(
                "{url} is {stats} at {}\r\n\r\n{header}\r\nStatus Code: {status}",
                local_dt
                    .with_timezone(&FixedOffset::east_opt(offset_in_seconds).unwrap())
                    .format("%a, %d %b %Y %H:%M:%S (GMT%:z)")
            )
        } else {
            log::error!("None");
            panic!("Header not supplied");
        }
    }
}

fn init_logger(level: LevelFilter) {
    let mut log_builder = env_logger::Builder::new();
    log_builder.format(|buf, record| {
        let mut module = "";
        if let Some(path) = record.module_path() {
            if let Some(split) = path.split("::").last() {
                module = split;
            }
        }

        writeln!(
            buf,
            "[{}][{}]> {}: {}",
            Local::now().format("%b-%d-%Y %H:%M:%S.%f"),
            record.level(),
            module,
            record.args()
        )
    });

    log_builder.filter_level(level);
    if let Err(e) = log_builder.try_init() {
        log::error!("{:?}", e);
    }
}
