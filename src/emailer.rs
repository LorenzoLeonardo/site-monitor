use chrono::{FixedOffset, Local};
use mail_send::{mail_builder::MessageBuilder, Credentials};
use oauth2::{
    http::{HeaderMap, StatusCode},
    AccessToken,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{SiteMonitorError, SiteMonitorResult},
    interface::Interface,
    profile, Stats,
};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Default)]
pub struct SmtpHostName(pub String);

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SmtpPort(pub u16);

pub async fn send_email<I: Interface + Clone>(
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
        profile::get_sender_profile(&token, &config.profile_url, interface.clone()).await?;

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
        .await
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

#[derive(Default)]
pub struct Emailer<I: Interface> {
    pub sender: (String, String),
    pub recipients: Vec<(String, String)>,
    interface: I,
}

impl<I> Emailer<I>
where
    I: Interface,
{
    pub fn new(interface: I) -> Self {
        Self {
            sender: (String::new(), String::new()),
            recipients: vec![],
            interface,
        }
    }

    pub fn set_sender(mut self, sender_name: String, sender_email: String) -> Self {
        self.sender = (sender_name, sender_email);
        self
    }

    pub fn add_recipient(mut self, recipient_name: String, recipient_email: String) -> Self {
        self.recipients.push((recipient_name, recipient_email));
        self
    }

    pub async fn send_email(
        self,
        access_token: &AccessToken,
        subject: &str,
        body: &str,
        html: Option<Vec<u8>>,
    ) -> SiteMonitorResult<()> {
        log::info!("E-mailing...");
        let mut message = MessageBuilder::new()
            .from(self.sender.to_owned())
            .to(self.recipients)
            .subject(subject)
            .text_body(body);
        if let Some(byte_vec) = html {
            message = message.html_body(String::from_utf8(byte_vec).unwrap());
        }

        let (_sender_name, sender_email) = self.sender;

        let credentials = Credentials::new_xoauth2(sender_email, access_token.secret().to_string());
        self.interface
            .send_email(credentials, message)
            .await
            .map(|_| {
                log::info!("E-mail send success!");
            })
            .map_err(|err| {
                log::info!("E-mail send failed! {err}");
                err
            })
    }
}
