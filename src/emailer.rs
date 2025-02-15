use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::AccessToken;
use serde::{Deserialize, Serialize};

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

    pub async fn send_email(
        self,
        access_token: &AccessToken,
        subject: &str,
        body: &str,
        html: Option<Vec<u8>>,
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
        let credentials =
            Credentials::new_xoauth2(sender_email.as_str(), access_token.secret().as_str());
        log::info!("Authenticating....");
        let email_connect = SmtpClientBuilder::new(self.smtp_server.0.as_ref(), self.smtp_port.0)
            .implicit_tls(false)
            .credentials(credentials)
            .connect()
            .await;

        match email_connect {
            Ok(mut result) => {
                log::info!("Sending Email....");
                let _ = result
                    .send(message)
                    .await
                    .map(|_| {
                        log::info!("Sending success!");
                    })
                    .map_err(|err| {
                        log::error!("Sending failed! {err}");
                    });
            }
            Err(err) => {
                log::error!("SMTP XOAUTH2 Credentials rejected!");
                log::error!("Error Details: {err:?}");
            }
        }
    }
}
