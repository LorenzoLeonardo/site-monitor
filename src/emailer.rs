use mail_send::{mail_builder::MessageBuilder, Credentials};
use oauth2::AccessToken;
use serde::{Deserialize, Serialize};

use crate::interface::Interface;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Default)]
pub struct SmtpHostName(pub String);

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SmtpPort(pub u16);

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
    ) {
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
        let _ = self
            .interface
            .send_email(credentials, message)
            .await
            .map(|_| {
                log::info!("E-mail send success!");
            })
            .map_err(|err| log::info!("E-mail send failed! {err}"));
    }
}
