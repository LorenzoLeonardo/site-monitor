mod auth;
mod emailer;
mod error;
mod profile;

use std::env;
use std::error::Error;
use std::io::Write;
use std::str::FromStr;
use std::time::Duration;

use async_curl::CurlActor;
use chrono::{FixedOffset, Local};
use curl_http_client::{Collector, ExtendedHandler, HttpClient};
use emailer::{Emailer, SmtpHostName, SmtpPort};
use error::{SiteMonitorError, SiteMonitorResult};
use futures::future;
use http::{HeaderMap, StatusCode};
use log::LevelFilter;
use oauth2::url::Url;
use oauth2::{AccessToken, DeviceAuthorizationUrl, Scope, TokenUrl};

use profile::{get_sender_profile, ProfileUrl};

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

    log::info!("Website Monitoring has started...");
    log::info!("Log {:?}", log_level);
    let actor = CurlActor::new();

    let _ = request_token(actor.clone()).await?;

    let site_to_monitor = [
        "https://img-corp.net",
        "https://kaiserhealthgroup.net",
        "https://www.rust-lang.org",
        "https://img-corp.com",
        "http://localhost:8080",
    ];

    let mut handle = Vec::new();
    for site in site_to_monitor {
        let actor_inner = actor.clone();
        handle.push(tokio::spawn(async move {
            if let Err(err) = monitor_site(actor_inner, site).await {
                log::error!("[{site}] {}", err.to_string());
            }
        }));
    }

    let _ = future::join_all(handle).await;
    Ok(())
}

async fn monitor_site(
    actor: CurlActor<Collector>,
    site_to_monitor: &str,
) -> Result<(), SiteMonitorError> {
    log::info!("Monitoring {site_to_monitor}...");

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
            .await?;

        let status_code = StatusCode::from_u16(response.response_code()? as u16)?;
        let (body, headers) = response.get_ref().get_response_body_and_headers();

        if status_code != StatusCode::OK {
            let headers = headers.ok_or(SiteMonitorError::new(
                error::ErrorCodes::HttpError,
                "No Headers".to_owned(),
            ))?;
            log::info!("[{}] {}", site_to_monitor, status_code);

            let token = request_token(actor.clone()).await?;
            send_email(
                &token,
                actor.clone(),
                site_to_monitor,
                &headers,
                status_code,
                body,
            )
            .await;

            tokio::time::sleep(Duration::from_secs(3600)).await;
        } else {
            log::debug!("[{}] {}", site_to_monitor, status_code);
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
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
    headers: &HeaderMap,
    status: StatusCode,
    html: Option<Vec<u8>>,
) {
    let header = headers
        .iter()
        .map(|(key, value)| format!("{}: {}", key.as_str(), value.to_str().unwrap_or("")))
        .collect::<Vec<String>>()
        .join("\r\n");
    let local_dt = Local::now();
    let offset_in_seconds = local_dt.offset().local_minus_utc();
    let report = format!(
        "{url} is down at {}\r\n\r\n{header}\r\nStatus Code:{status}",
        local_dt
            .with_timezone(&FixedOffset::east_opt(offset_in_seconds).unwrap())
            .format("%a, %d %b %Y %H:%M:%S (GMT%:z)")
    );

    let (_sender_name, sender_email) = get_sender_profile(
        &token,
        &ProfileUrl(Url::from_str(PROFILE_URL).unwrap()),
        curl,
    )
    .await
    .unwrap();

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
        .await
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
            "{}[{}]> {}: {}",
            Local::now().format("[%b-%d-%Y %H:%M:%S.%f]"),
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
