use mail_send::{mail_builder::MessageBuilder, Credentials};
use oauth2::AccessToken;
use serde::{Deserialize, Serialize};

use crate::interface::Interface;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Default)]
pub struct SmtpHostName(pub String);

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SmtpPort(pub u16);

#[derive(Default)]
pub struct Emailer {
    pub smtp_server: SmtpHostName,
    pub smtp_port: SmtpPort,
    pub sender: (String, String),
    pub recipients: Vec<(String, String)>,
}

impl Emailer {
    pub fn new(smtp_server: SmtpHostName, smtp_port: SmtpPort) -> Self {
        Self {
            smtp_server,
            smtp_port,
            ..Default::default()
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

    pub async fn send_email<I: Interface>(
        self,
        access_token: &AccessToken,
        subject: &str,
        body: &str,
        html: Option<Vec<u8>>,
        interface: I,
    ) {
        // Start of sending Email
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
        let _ = interface
            .send_email(credentials, message)
            .await
            .map(|_| {
                log::info!("E-mail send success!");
            })
            .map_err(|err| log::info!("E-mail send failed! {err}"));
    }
}
