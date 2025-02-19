use std::time::Duration;

use oauth2::{http::StatusCode, HttpResponse};

use crate::{
    auth, emailer,
    error::{SiteMonitorError, SiteMonitorResult},
    interface::Interface,
    Stats,
};

pub async fn monitor_site<I: Interface + Clone + Send>(
    interface: I,
    site_to_monitor: &str,
) -> Result<(), SiteMonitorError> {
    let mut was_down = false;

    loop {
        let response = interface.website_curl_perform(site_to_monitor).await;
        was_down =
            handle_web_result(interface.clone(), site_to_monitor, was_down, response).await?;
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn handle_web_result<I: Interface + Clone + Send>(
    interface: I,
    site_to_monitor: &str,
    mut was_down: bool,
    response: SiteMonitorResult<HttpResponse>,
) -> SiteMonitorResult<bool> {
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
                )
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
                )
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
                )
            }
        }
    }
    Ok(was_down)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        str::FromStr,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use log::LevelFilter;
    use oauth2::{
        http::{header::CONTENT_TYPE, HeaderValue, StatusCode},
        AccessToken, HttpResponse, RefreshToken,
    };
    use tempfile::TempDir;
    use test_case::test_case;

    use crate::{
        auth::TokenKeeper,
        config::Config,
        error::{ErrorCodes, SiteMonitorError, SiteMonitorResult},
        interface::{mock::MockInterface, Interface},
        monitor::handle_web_result,
    };

    fn success_token() -> HttpResponse {
        let json = r#"
        {
            "token_type": "Bearer",
            "scope": "User.Read profile openid email",
            "expires_in": 3599,
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1Q...",
            "refresh_token": "AwABAAAAvPM1KaPlrEqdFSBzjqfTGAMxZGUTdM0t4B4...",
            "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIyZDRkMTFhMi1mODE0LTQ2YTctOD..."
        }
        "#.as_bytes().to_vec();
        let mut response = HttpResponse::new(json);
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/json").unwrap(),
        );

        *response.status_mut() = StatusCode::OK;
        response
    }

    fn create_token_file(path: &Path, config: &Config) {
        let keeper = TokenKeeper {
            access_token: AccessToken::new("testaccesstoken".into()),
            refresh_token: Some(RefreshToken::new("testrefreshtoken".into())),
            scopes: Some(Vec::new()),
            expires_in: Some(Duration::from_secs(60)),
            token_receive_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards"),
            file_directory: PathBuf::new(),
        };
        let file = config.client_id.clone() + &String::from_str("_device_code_flow.json").unwrap();
        let path = path.join(file);
        eprintln!("path: {:?}", path);

        let _ = fs::write(path, serde_json::to_string(&keeper).unwrap());
    }

    fn create_profile_response() -> HttpResponse {
        let ms_json = r#"{
            "@odata.context": "data context",
            "@odata.id": "data id",
            "Id": "sample id",
            "EmailAddress": "test@outlook.com",
            "DisplayName": "My Name",
            "Alias": "Haxxx",
            "MailboxGuid": "en"
          }"#;

        let http_response = HttpResponse::new(ms_json.as_bytes().to_vec());
        http_response
    }
    #[tokio::test]
    #[test_case("https://localhost", false, StatusCode::OK, Ok(success_token()), Ok(()), Ok(false); "was_down=false StatusCode=200")]
    #[test_case("https://localhost", false, StatusCode::BAD_GATEWAY, Ok(success_token()), Ok(()), Ok(true); "was_down=false StatusCode=502")]
    #[test_case("https://localhost", true, StatusCode::OK, Ok(success_token()), Ok(()), Ok(false); "was_down=true StatusCode=200")]
    #[test_case("https://localhost", true, StatusCode::BAD_GATEWAY, Ok(success_token()), Ok(()), Ok(true); "was_down=true StatusCode=502")]
    #[test_case("https://localhost", true, StatusCode::OK, Err(SiteMonitorError::new(ErrorCodes::CurlError, String::new())), Ok(()), Ok(false); "CurlError StatusCode=200")]
    #[test_case("https://localhost", true, StatusCode::BAD_GATEWAY, Err(SiteMonitorError::new(ErrorCodes::CurlError, String::new())), Ok(()), Ok(true); "CurlError StatusCode=502")]
    #[test_case("https://localhost", false, StatusCode::OK, Ok(success_token()), Err(SiteMonitorError::new(ErrorCodes::Emailer, String::new())), Ok(false); "Email Error was_down=false StatusCode=200")]
    #[test_case("https://localhost", false, StatusCode::BAD_GATEWAY, Ok(success_token()), Err(SiteMonitorError::new(ErrorCodes::Emailer, String::new())), Ok(false); "Email Error was_down=false StatusCode=502")]
    #[test_case("https://localhost", true, StatusCode::OK, Ok(success_token()), Err(SiteMonitorError::new(ErrorCodes::Emailer, String::new())), Ok(true); "Email Error was_down=true StatusCode=200")]
    #[test_case("https://localhost", true, StatusCode::BAD_GATEWAY, Ok(success_token()), Err(SiteMonitorError::new(ErrorCodes::Emailer, String::new())), Ok(true); "Email Error was_down=true StatusCode=502")]
    async fn test_monitor(
        site_to_monitor: &str,
        was_down: bool,
        status_code: StatusCode,
        oauth2_response: SiteMonitorResult<HttpResponse>,
        email_response: SiteMonitorResult<()>,
        expected: SiteMonitorResult<bool>,
    ) {
        crate::init_logger(LevelFilter::Debug);
        let mut interface = MockInterface::new();

        let mut response = HttpResponse::new(Vec::new());
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/json").unwrap(),
        );

        *response.status_mut() = status_code;

        interface.set_website_perform_response(Ok(response.clone()));
        interface.set_oauth2_perform_response(oauth2_response);
        interface.set_profile_perform_response(Ok(create_profile_response()));
        interface.set_send_mail_response(email_response);

        let tempdir = TempDir::with_prefix_in("test", "").unwrap();
        interface.set_token_path(tempdir.path());

        create_token_file(tempdir.path(), &interface.get_config());

        let response = interface.website_curl_perform(site_to_monitor).await;
        let result = handle_web_result(interface, site_to_monitor, was_down, response).await;
        eprintln!("Result: {:?}", result);
        assert_eq!(result, expected);
    }
}
