mod auth;
mod emailer;
mod error;
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
use curl_http_client::{Collector, ExtendedHandler, HttpClient};
use emailer::{Emailer, SmtpHostName, SmtpPort};
use error::{SiteMonitorError, SiteMonitorResult};
use log::LevelFilter;
use oauth2::http::{HeaderMap, StatusCode};
use oauth2::url::Url;
use oauth2::{AccessToken, DeviceAuthorizationUrl, Scope, TokenUrl};
use tokio::select;
use tokio::sync::mpsc::channel;

use profile::{get_sender_profile, ProfileUrl};
use watcher::{watch_file, WatcherAction};

const DEVICE_AUTH_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode";
const TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const PROFILE_URL: &str = "https://outlook.office.com/api/v2.0/me";
const CLIENT_ID: &str = "f7c886f5-00f6-4981-b000-b4d5ab0e5ef2";
const SMTP_SERVER: &str = "smtp.office365.com";
const SMTP_PORT: u16 = 587;
const SCOPES: &'static [&str] = &[
    "offline_access",
    "https://outlook.office.com/SMTP.Send",
    "https://outlook.office.com/User.Read",
];

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

    let actor = CurlActor::new();
    let _ = request_token(actor.clone()).await?;
    let (tx, mut rx) = channel(1);
    let _ = watch_file(tx, PathBuf::from_str("websites.txt")?).await;

    let mut hash_map_task = HashMap::new();

    loop {
        select! {
            Some(msg) = rx.recv() => {
                match msg {
                    WatcherAction::Add(sites) => {
                        for site in sites {
                            let actor_inner = actor.clone();
                            let site_inner = site.clone();
                            let handle = tokio::spawn(async move {
                                if let Err(err) = monitor_site(actor_inner, site_inner.as_str()).await {
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

async fn monitor_site(
    actor: CurlActor<Collector>,
    site_to_monitor: &str,
) -> Result<(), SiteMonitorError> {
    let mut was_down = false;
    let collector = Collector::RamAndHeaders(Vec::new(), Vec::new());

    loop {
        let response = HttpClient::new(collector.clone())
            .url(site_to_monitor)?
            .follow_location(true)?
            .connect_timeout(Duration::from_secs(30))?
            .timeout(Duration::from_secs(30))?
            .nobody(true)?
            .nonblocking(actor.clone())
            .send_request()
            .await;

        match response {
            Ok(response) => {
                let status_code = StatusCode::from_u16(response.response_code()? as u16)?;
                let (body, headers) = response.get_ref().get_response_body_and_headers();
                log::debug!("[{}] {}", site_to_monitor, status_code);

                let headers = headers.ok_or(SiteMonitorError::new(
                    error::ErrorCodes::HttpError,
                    "No Headers".to_owned(),
                ))?;

                if (status_code != StatusCode::OK) && !was_down {
                    log::info!("[{}] {}, is down!", site_to_monitor, status_code);
                    let token = request_token(actor.clone()).await?;
                    let _ = send_email(
                        &token,
                        actor.clone(),
                        site_to_monitor,
                        Some((&headers, status_code)),
                        body,
                        Stats::Down,
                        None,
                    )
                    .await;
                    was_down = true;
                } else if (status_code == StatusCode::OK) && was_down {
                    log::info!("[{}] {}, is up!", site_to_monitor, status_code);
                    let token = request_token(actor.clone()).await?;
                    let _ = send_email(
                        &token,
                        actor.clone(),
                        site_to_monitor,
                        Some((&headers, status_code)),
                        body,
                        Stats::Up,
                        None,
                    )
                    .await;
                    was_down = false
                }
            }
            Err(err) => {
                let error: SiteMonitorError = err.into();
                log::error!("[{}] {}", site_to_monitor, error);

                if !was_down {
                    let token = request_token(actor.clone()).await?;
                    let _ = send_email(
                        &token,
                        actor.clone(),
                        site_to_monitor,
                        None,
                        None,
                        Stats::Down,
                        Some(error),
                    )
                    .await;
                    was_down = true;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn request_token(actor: CurlActor<Collector>) -> SiteMonitorResult<AccessToken> {
    let scopes = SCOPES.iter().map(|&s| Scope::new(s.to_string())).collect();
    auth::device_code_flow(
        CLIENT_ID,
        None,
        DeviceAuthorizationUrl::new(DEVICE_AUTH_URL.to_string())?,
        TokenUrl::new(TOKEN_URL.to_string())?,
        scopes,
        actor,
    )
    .await
}

async fn send_email(
    token: &AccessToken,
    curl: CurlActor<Collector>,
    url: &str,
    header_status: Option<(&HeaderMap, StatusCode)>,
    html: Option<Vec<u8>>,
    stats: Stats,
    error: Option<SiteMonitorError>,
) -> SiteMonitorResult<()> {
    let (_sender_name, sender_email) = get_sender_profile(
        &token,
        &ProfileUrl(Url::from_str(PROFILE_URL).unwrap()),
        curl,
    )
    .await?;

    let report = format_email_report(url, header_status, stats, error);

    Emailer::new(SmtpHostName(SMTP_SERVER.to_string()), SmtpPort(SMTP_PORT))
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
