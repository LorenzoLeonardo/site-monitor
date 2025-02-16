use std::str::FromStr;

use derive_deref_rs::Deref;
use oauth2::{
    http::{HeaderMap, HeaderName, HeaderValue},
    url::Url,
    AccessToken, HttpRequest,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{SiteMonitorError, SiteMonitorResult},
    interface::Interface,
};

#[derive(Deref, Debug, PartialEq)]
pub struct SenderName(pub String);
#[derive(Deref, Debug, PartialEq)]
pub struct SenderEmail(pub String);

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MicrosoftProfile {
    #[serde(rename = "@odata.context")]
    odata_context: String,
    #[serde(rename = "@odata.id")]
    odata_id: String,
    id: String,
    email_address: String,
    display_name: String,
    alias: String,
    mailbox_guid: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GoogleProfile {
    id: String,
    email: String,
    verified_email: bool,
    name: String,
    given_name: String,
    picture: String,
    locale: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Profile {
    Microsoft(MicrosoftProfile),
    Google(GoogleProfile),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProfileUrl(pub Url);

pub async fn get_sender_profile<I: Interface>(
    access_token: &AccessToken,
    profile_endpoint: &ProfileUrl,
    interface: I,
) -> SiteMonitorResult<(SenderName, SenderEmail)> {
    let mut headers = HeaderMap::new();

    let header_val = format!("Bearer {}", access_token.secret().as_str());
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&header_val).map_err(SiteMonitorError::from)?,
    );
    let mut request = HttpRequest::new(Vec::new());
    *request.uri_mut() = oauth2::http::Uri::from_str(profile_endpoint.0.to_owned().as_ref())?;
    *request.method_mut() = oauth2::http::Method::GET;

    request.headers_mut().insert(
        HeaderName::from_str("Authorization")?,
        HeaderValue::from_str(&header_val)?,
    );

    let response = interface.profile_curl_perform(request).await?;

    let body = String::from_utf8(response.body().to_vec()).unwrap_or_default();

    let sender_profile: Profile = serde_json::from_str(&body)?;
    let (name, email) = match sender_profile {
        Profile::Microsoft(profile) => {
            log::debug!("Response: {:?}", profile);
            (
                SenderName(profile.display_name),
                SenderEmail(profile.email_address),
            )
        }
        Profile::Google(profile) => {
            log::debug!("Response: {:?}", profile);
            (SenderName(profile.given_name), SenderEmail(profile.email))
        }
    };
    log::debug!("Sender Name: {}", name.as_str());
    log::debug!("Sender E-mail: {}", email.as_str());
    Ok((name, email))
}

#[cfg(test)]
mod tests {
    use oauth2::{url::Url, AccessToken, HttpResponse};

    use crate::{
        error::{ErrorCodes, SiteMonitorError},
        interface::mock::MockInterface,
        profile::{get_sender_profile, Profile, ProfileUrl, SenderEmail, SenderName},
    };

    #[test]
    fn test_google_profile() {
        let google_json = r#"{
            "id": "1525363627",
            "email": "test@gmail.com",
            "verified_email": true,
            "name": "My Name",
            "given_name": "My Name",
            "picture": "https://picutre",
            "locale": "en"
          }"#;

        let google: Profile = serde_json::from_str(google_json).unwrap();

        if let Profile::Google(google) = google {
            println!("deserialize = {:?}", &google);
            println!("serialize = {:?}", serde_json::to_string(&google).unwrap());
        } else {
            panic!("Not Google");
        }
    }

    #[test]
    fn test_microsoft_profile() {
        let ms_json = r#"{
            "@odata.context": "data context",
            "@odata.id": "data id",
            "Id": "sample id",
            "EmailAddress": "test@outlook.com",
            "DisplayName": "My Name",
            "Alias": "Haxxx",
            "MailboxGuid": "en"
          }"#;

        let ms: Profile = serde_json::from_str(ms_json).unwrap();

        if let Profile::Microsoft(ms) = ms {
            println!("deserialize = {:?}", &ms);
            println!("serialize = {:?}", serde_json::to_string(&ms).unwrap());
        } else {
            panic!("Not Microsoft");
        }
    }

    #[tokio::test]
    async fn test_get_sender_profile_good() {
        let ms_json = r#"{
            "@odata.context": "data context",
            "@odata.id": "data id",
            "Id": "sample id",
            "EmailAddress": "test@outlook.com",
            "DisplayName": "My Name",
            "Alias": "Haxxx",
            "MailboxGuid": "en"
          }"#;

        let mut interface = MockInterface::new();
        let http_response = HttpResponse::new(ms_json.as_bytes().to_vec());
        interface.set_profile_perform_response(Ok(http_response));

        let (sender, email) = get_sender_profile(
            &AccessToken::new("My_token".into()),
            &ProfileUrl(Url::parse("https://localhost").unwrap()),
            interface,
        )
        .await
        .unwrap();

        println!("SenderName: {:?}", sender);
        println!("Email: {:?}", email);
        assert_eq!(sender, SenderName("My Name".into()));
        assert_eq!(email, SenderEmail("test@outlook.com".into()));
    }

    #[tokio::test]
    async fn test_get_sender_profile_bad() {
        let mut interface = MockInterface::new();

        interface.set_profile_perform_response(Err(SiteMonitorError::new(
            crate::error::ErrorCodes::CurlError,
            "Curl Error".into(),
        )));

        let result = get_sender_profile(
            &AccessToken::new("My_token".into()),
            &ProfileUrl(Url::parse("https://localhost").unwrap()),
            interface,
        )
        .await
        .unwrap_err();

        assert_eq!(
            result,
            SiteMonitorError::new(crate::error::ErrorCodes::CurlError, "Curl Error".into(),)
        );
    }

    #[tokio::test]
    async fn test_get_sender_profile_bad_json() {
        let ms_json = r#"{
            "@odata.context": "data context",
            "@odata.id": "data id",
            "Id": "sample id",
            "EmailAddress": "test@outlook.com",
            "DisplayName": "My Name",
            "Alias: "Haxxx",
            "MailboxGuid": "en"
          }"#;

        let mut interface = MockInterface::new();
        let http_response = HttpResponse::new(ms_json.as_bytes().to_vec());
        interface.set_profile_perform_response(Ok(http_response));

        let result = get_sender_profile(
            &AccessToken::new("My_token".into()),
            &ProfileUrl(Url::parse("https://localhost").unwrap()),
            interface,
        )
        .await
        .unwrap_err();

        assert_eq!(result.error_code, ErrorCodes::SerdeJsonParseError);
    }
}
