mod auth;
mod curl;
mod emailer;
mod error;
mod profile;

use std::io::Write;
use std::str::FromStr;
use std::time::Duration;

use async_curl::CurlActor;
use chrono::{FixedOffset, Local};
use curl::Curl;
use curl_http_client::{Collector, HttpClient};
use emailer::{Emailer, SmtpHostName, SmtpPort};
use http::{HeaderMap, StatusCode};
use log::LevelFilter;
use oauth2::url::Url;
use oauth2::{AccessToken, DeviceAuthorizationUrl, Scope, TokenUrl};
use profile::{get_sender_profile, ProfileUrl};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    init_logger("info");

    let curl = Curl::new();
    let token = login(curl.clone()).await;

    log::info!("AccessToken: {:?}", token);
    let actor = CurlActor::new();
    let collector = Collector::RamAndHeaders(Vec::new(), Vec::new());
    let site_to_monitor = "https://img-corp.net";
    loop {
        let client = HttpClient::new(collector.clone())
            .url(site_to_monitor)
            .unwrap()
            .follow_location(true)
            .unwrap()
            .nobody(true)
            .unwrap()
            .nonblocking(actor.clone())
            .perform()
            .await
            .unwrap();

        if client.status() == StatusCode::OK {
            println!("Website is good");
        } else {
            let headers = client.headers();
            println!("Website is bad: {}", client.status());
            let token = login(curl.clone()).await;
            send_email(
                &token,
                curl.clone(),
                site_to_monitor,
                headers,
                client.status(),
            )
            .await;

            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn login(curl: Curl) -> AccessToken {
    auth::device_code_flow(
        "f7c886f5-00f6-4981-b000-b4d5ab0e5ef2",
        None,
        DeviceAuthorizationUrl::new(
            "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".to_string(),
        )
        .unwrap(),
        TokenUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string())
            .unwrap(),
        vec![
            Scope::new("offline_access".to_string()),
            Scope::new("https://outlook.office.com/SMTP.Send".to_string()),
            Scope::new("https://outlook.office.com/User.Read".to_string()),
        ],
        curl,
    )
    .await
    .unwrap()
}

async fn send_email(
    token: &AccessToken,
    curl: Curl,
    url: &str,
    headers: &HeaderMap,
    status: StatusCode,
) {
    let header = headers
        .iter()
        .map(|(key, value)| format!("{}: {}", key.as_str(), value.to_str().unwrap_or("")))
        .collect::<Vec<String>>()
        .join("\r\n");
    let report = format!(
        "{url} is down at {}\r\n\r\n{header}\r\nStatus Code:{status}",
        Local::now()
            .with_timezone(&FixedOffset::east_opt(8 * 3600).unwrap())
            .format("%Y-%m-%d %H:%M:%S (GMT%:z)")
    );

    let (_sender_name, sender_email) = get_sender_profile(
        &token,
        &ProfileUrl(Url::from_str("https://outlook.office.com/api/v2.0/me").unwrap()),
        curl,
    )
    .await
    .unwrap();

    Emailer::new(
        SmtpHostName("smtp.office365.com".to_string()),
        SmtpPort(587),
    )
    .set_sender("Enzo Tech Web Monitor".to_string(), sender_email.0)
    .add_recipient(
        "Lorenzo Leonardo".into(),
        "enzotechcomputersolutions@gmail.com".into(),
    )
    .send_email(token, "Enzo Tech Web Monitoring Report", report.as_str())
    .await
    .unwrap()
}

fn init_logger(level: &str) {
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
            "{}[{}]:{}: {}",
            Local::now().format("[%d-%m-%Y %H:%M:%S]"),
            record.level(),
            module,
            record.args()
        )
    });

    log_builder.filter_level(LevelFilter::from_str(level).unwrap_or(LevelFilter::Info));
    if let Err(e) = log_builder.try_init() {
        log::error!("{:?}", e);
    }
}
