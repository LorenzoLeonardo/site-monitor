// Standard libraries
use std::fmt::{Debug, Display};
use std::{error::Error, str::FromStr};

// 3rd party crates
use curl_http_client::collector::ExtendedHandler;
use curl_http_client::dep::async_curl;
use log::SetLoggerError;
use oauth2::http::header::{InvalidHeaderName, InvalidHeaderValue, ToStrError};
use oauth2::http::method::InvalidMethod;
use oauth2::http::status::InvalidStatusCode;
use oauth2::http::uri::InvalidUri;
use oauth2::{
    url, ConfigurationError, ErrorResponseType, RequestTokenError, StandardErrorResponse,
};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

#[derive(Serialize, Deserialize, Debug, PartialEq, EnumString, Display, Clone)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ErrorCodes {
    // Cloud error codes
    AccessDenied,
    AuthorizationDeclined,
    AuthorizationPending,
    BadVerificationCode,
    BadRequest,
    ConsentRequired,
    ExpiredToken,
    Forbidden,
    InsufficientScope,
    InteractionRequired,
    InvalidClient,
    InvalidGrant,
    InvalidRedirectUri,
    InvalidResource,
    InvalidRequest,
    InvalidScope,
    InvalidToken,
    LoginRequired,
    MappingError,
    ServerError,
    SlowDown,
    TemporarilyUnavailable,
    Unauthorized,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    UnsupportedTokenType,

    // Local error codes
    ConfigurationError,
    CurlError,
    DirectoryError,
    HttpError,
    InvalidParameters,
    IoError,
    LoggerError,
    MultiError,
    NoToken,
    OtherError,
    ParseError,
    PerformError,
    RequestError,
    SerdeJsonParseError,
    TokioRecv,
    TokioSend,
    UrlParseError,
    Emailer,
}

impl From<String> for ErrorCodes {
    fn from(str: String) -> Self {
        ErrorCodes::from_str(str.as_str()).unwrap_or(ErrorCodes::OtherError)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct SiteMonitorError {
    pub error_code: ErrorCodes,
    pub error_code_desc: String,
}

impl SiteMonitorError {
    pub fn new(error_code: ErrorCodes, error_code_desc: String) -> Self {
        Self {
            error_code,
            error_code_desc,
        }
    }
}

impl From<ConfigurationError> for SiteMonitorError {
    fn from(e: ConfigurationError) -> Self {
        SiteMonitorError::new(ErrorCodes::ConfigurationError, e.to_string())
    }
}

impl From<url::ParseError> for SiteMonitorError {
    fn from(e: url::ParseError) -> Self {
        SiteMonitorError::new(ErrorCodes::UrlParseError, e.to_string())
    }
}

impl<O> From<StandardErrorResponse<O>> for ErrorCodes
where
    O: ErrorResponseType + 'static + ToString,
{
    fn from(e: StandardErrorResponse<O>) -> Self {
        ErrorCodes::from(e.error().to_string())
    }
}

impl<E, O> From<RequestTokenError<E, StandardErrorResponse<O>>> for SiteMonitorError
where
    E: Error + 'static,
    O: ErrorResponseType + 'static + ToString + Clone + Display,
{
    fn from(e: RequestTokenError<E, StandardErrorResponse<O>>) -> Self {
        match e {
            RequestTokenError::ServerResponse(err) => {
                let desc = err
                    .error_description()
                    .map(|ret| ret.to_string())
                    .unwrap_or_default();
                SiteMonitorError::new(ErrorCodes::from(err.clone()), desc)
            }
            RequestTokenError::Request(err) => {
                SiteMonitorError::new(ErrorCodes::RequestError, err.to_string())
            }
            RequestTokenError::Parse(err, _data) => {
                SiteMonitorError::new(ErrorCodes::ParseError, err.to_string())
            }
            RequestTokenError::Other(err) => SiteMonitorError::new(ErrorCodes::OtherError, err),
        }
    }
}

impl From<serde_json::Error> for SiteMonitorError {
    fn from(e: serde_json::Error) -> Self {
        SiteMonitorError::new(ErrorCodes::SerdeJsonParseError, e.to_string())
    }
}

impl From<std::io::Error> for SiteMonitorError {
    fn from(e: std::io::Error) -> Self {
        SiteMonitorError::new(ErrorCodes::IoError, e.to_string())
    }
}

impl From<SetLoggerError> for SiteMonitorError {
    fn from(e: SetLoggerError) -> Self {
        SiteMonitorError::new(ErrorCodes::LoggerError, e.to_string())
    }
}

impl<C> From<curl_http_client::error::Error<C>> for SiteMonitorError
where
    C: ExtendedHandler + Debug + Send + 'static,
{
    fn from(e: curl_http_client::error::Error<C>) -> Self {
        match e {
            curl_http_client::error::Error::Curl(err) => SiteMonitorError::new(
                ErrorCodes::CurlError,
                format!("{}({})", err.description(), err.code()),
            ),
            curl_http_client::error::Error::Http(err) => {
                SiteMonitorError::new(ErrorCodes::HttpError, err)
            }
            curl_http_client::error::Error::Perform(err) => match err {
                async_curl::error::Error::Curl(err) => SiteMonitorError::new(
                    ErrorCodes::CurlError,
                    format!("{}({})", err.description(), err.code()),
                ),
                async_curl::error::Error::Multi(err) => SiteMonitorError::new(
                    ErrorCodes::MultiError,
                    format!("{}({})", err.description(), err.code()),
                ),
                async_curl::error::Error::TokioRecv(err) => {
                    SiteMonitorError::new(ErrorCodes::TokioRecv, err.to_string())
                }
                async_curl::error::Error::TokioSend(err) => {
                    SiteMonitorError::new(ErrorCodes::TokioSend, err.to_string())
                }
            },
            curl_http_client::error::Error::Other(err) => {
                SiteMonitorError::new(ErrorCodes::OtherError, err)
            }
        }
    }
}

impl From<InvalidHeaderValue> for SiteMonitorError {
    fn from(e: InvalidHeaderValue) -> Self {
        SiteMonitorError::new(ErrorCodes::HttpError, e.to_string())
    }
}

impl From<InvalidUri> for SiteMonitorError {
    fn from(e: InvalidUri) -> Self {
        SiteMonitorError::new(ErrorCodes::HttpError, e.to_string())
    }
}

impl From<InvalidMethod> for SiteMonitorError {
    fn from(e: InvalidMethod) -> Self {
        SiteMonitorError::new(ErrorCodes::HttpError, e.to_string())
    }
}

impl From<InvalidHeaderName> for SiteMonitorError {
    fn from(e: InvalidHeaderName) -> Self {
        SiteMonitorError::new(ErrorCodes::HttpError, e.to_string())
    }
}

impl From<ToStrError> for SiteMonitorError {
    fn from(e: ToStrError) -> Self {
        SiteMonitorError::new(ErrorCodes::HttpError, e.to_string())
    }
}

impl From<curl_http_client::dep::curl::Error> for SiteMonitorError {
    fn from(e: curl_http_client::dep::curl::Error) -> Self {
        SiteMonitorError::new(
            ErrorCodes::CurlError,
            format!("{}({})", e.description(), e.code()),
        )
    }
}

impl From<InvalidStatusCode> for SiteMonitorError {
    fn from(e: InvalidStatusCode) -> Self {
        SiteMonitorError::new(ErrorCodes::HttpError, e.to_string())
    }
}

impl From<mail_send::Error> for SiteMonitorError {
    fn from(e: mail_send::Error) -> Self {
        SiteMonitorError::new(ErrorCodes::Emailer, e.to_string())
    }
}

impl std::fmt::Display for SiteMonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "code: {} description: {}",
            self.error_code, self.error_code_desc
        )
    }
}

impl Debug for SiteMonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "code: {} description: {}",
            self.error_code, self.error_code_desc
        )
    }
}

impl std::error::Error for SiteMonitorError {}

pub type SiteMonitorResult<T> = Result<T, SiteMonitorError>;

#[cfg(test)]
mod tests {
    use super::ErrorCodes;

    #[test]
    fn test_error_codes_to_json_snake_case() {
        assert_eq!(
            serde_json::to_string(&ErrorCodes::BadRequest)
                .unwrap_or(String::from("\"bad_request\"")),
            String::from("\"bad_request\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::Unauthorized)
                .unwrap_or(String::from("\"unauthorized\"")),
            String::from("\"unauthorized\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::Forbidden).unwrap_or(String::from("\"forbidden\"")),
            String::from("\"forbidden\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::InvalidRequest)
                .unwrap_or(String::from("\"invalid_request\"")),
            String::from("\"invalid_request\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UnauthorizedClient)
                .unwrap_or(String::from("\"unauthorized_client\"")),
            String::from("\"unauthorized_client\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::AccessDenied)
                .unwrap_or(String::from("\"access_denied\"")),
            String::from("\"access_denied\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UnsupportedResponseType)
                .unwrap_or(String::from("\"unsupported_response_type\"")),
            String::from("\"unsupported_response_type\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::InvalidScope)
                .unwrap_or(String::from("\"invalid_scope\"")),
            String::from("\"invalid_scope\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::ServerError)
                .unwrap_or(String::from("\"server_error\"")),
            String::from("\"server_error\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::TemporarilyUnavailable)
                .unwrap_or(String::from("\"temporarily_unavailable\"")),
            String::from("\"temporarily_unavailable\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::InvalidClient)
                .unwrap_or(String::from("\"invalid_client\"")),
            String::from("\"invalid_client\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::InvalidGrant)
                .unwrap_or(String::from("\"invalid_grant\"")),
            String::from("\"invalid_grant\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UnsupportedTokenType)
                .unwrap_or(String::from("\"unsupported_token_type\"")),
            String::from("\"unsupported_token_type\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UnsupportedGrantType)
                .unwrap_or(String::from("\"unsupported_grant_type\"")),
            String::from("\"unsupported_grant_type\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::AuthorizationPending)
                .unwrap_or(String::from("\"authorization_pending\"")),
            String::from("\"authorization_pending\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::SlowDown).unwrap_or(String::from("\"slow_down\"")),
            String::from("\"slow_down\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::ExpiredToken)
                .unwrap_or(String::from("\"expired_token\"")),
            String::from("\"expired_token\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::ConfigurationError)
                .unwrap_or(String::from("\"configuration_error\"")),
            String::from("\"configuration_error\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::UrlParseError)
                .unwrap_or(String::from("\"url_parse_error\"")),
            String::from("\"url_parse_error\"")
        );
        assert_eq!(
            serde_json::to_string(&ErrorCodes::OtherError)
                .unwrap_or(String::from("\"other_error\"")),
            String::from("\"other_error\"")
        );
    }
    #[test]
    fn test_json_snake_case_to_error_codes() {
        assert_eq!(
            serde_json::from_str("\"bad_request\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::BadRequest
        );
        assert_eq!(
            serde_json::from_str("\"unauthorized\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::Unauthorized
        );
        assert_eq!(
            serde_json::from_str("\"forbidden\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::Forbidden
        );
        assert_eq!(
            serde_json::from_str("\"invalid_request\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::InvalidRequest
        );
        assert_eq!(
            serde_json::from_str("\"unauthorized_client\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UnauthorizedClient
        );
        assert_eq!(
            serde_json::from_str("\"access_denied\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::AccessDenied
        );
        assert_eq!(
            serde_json::from_str("\"unsupported_response_type\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UnsupportedResponseType
        );
        assert_eq!(
            serde_json::from_str("\"invalid_scope\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::InvalidScope
        );
        assert_eq!(
            serde_json::from_str("\"server_error\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::ServerError
        );
        assert_eq!(
            serde_json::from_str("\"temporarily_unavailable\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::TemporarilyUnavailable
        );
        assert_eq!(
            serde_json::from_str("\"invalid_client\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::InvalidClient
        );
        assert_eq!(
            serde_json::from_str("\"invalid_grant\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::InvalidGrant
        );
        assert_eq!(
            serde_json::from_str("\"unsupported_token_type\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UnsupportedTokenType
        );
        assert_eq!(
            serde_json::from_str("\"unsupported_grant_type\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UnsupportedGrantType
        );
        assert_eq!(
            serde_json::from_str("\"authorization_pending\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::AuthorizationPending
        );
        assert_eq!(
            serde_json::from_str("\"slow_down\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::SlowDown
        );
        assert_eq!(
            serde_json::from_str("\"expired_token\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::ExpiredToken
        );
        assert_eq!(
            serde_json::from_str("\"configuration_error\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::ConfigurationError
        );
        assert_eq!(
            serde_json::from_str("\"url_parse_error\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::UrlParseError
        );
        assert_eq!(
            serde_json::from_str("\"other_error\"").unwrap_or(ErrorCodes::OtherError),
            ErrorCodes::OtherError
        );
    }
    #[test]
    fn test_string_snake_case_to_error_codes() {
        assert_eq!(
            ErrorCodes::from(String::from("bad_request")),
            ErrorCodes::BadRequest
        );
        assert_eq!(
            ErrorCodes::from(String::from("unauthorized")),
            ErrorCodes::Unauthorized
        );
        assert_eq!(
            ErrorCodes::from(String::from("forbidden")),
            ErrorCodes::Forbidden
        );
        assert_eq!(
            ErrorCodes::from(String::from("invalid_request")),
            ErrorCodes::InvalidRequest
        );
        assert_eq!(
            ErrorCodes::from(String::from("unauthorized_client")),
            ErrorCodes::UnauthorizedClient
        );
        assert_eq!(
            ErrorCodes::from(String::from("access_denied")),
            ErrorCodes::AccessDenied
        );
        assert_eq!(
            ErrorCodes::from(String::from("unsupported_response_type")),
            ErrorCodes::UnsupportedResponseType
        );
        assert_eq!(
            ErrorCodes::from(String::from("invalid_scope")),
            ErrorCodes::InvalidScope
        );
        assert_eq!(
            ErrorCodes::from(String::from("server_error")),
            ErrorCodes::ServerError
        );
        assert_eq!(
            ErrorCodes::from(String::from("temporarily_unavailable")),
            ErrorCodes::TemporarilyUnavailable
        );
        assert_eq!(
            ErrorCodes::from(String::from("invalid_client")),
            ErrorCodes::InvalidClient
        );
        assert_eq!(
            ErrorCodes::from(String::from("invalid_grant")),
            ErrorCodes::InvalidGrant
        );
        assert_eq!(
            ErrorCodes::from(String::from("unsupported_token_type")),
            ErrorCodes::UnsupportedTokenType
        );
        assert_eq!(
            ErrorCodes::from(String::from("unsupported_grant_type")),
            ErrorCodes::UnsupportedGrantType
        );
        assert_eq!(
            ErrorCodes::from(String::from("authorization_pending")),
            ErrorCodes::AuthorizationPending
        );
        assert_eq!(
            ErrorCodes::from(String::from("slow_down")),
            ErrorCodes::SlowDown
        );
        assert_eq!(
            ErrorCodes::from(String::from("expired_token")),
            ErrorCodes::ExpiredToken
        );
        assert_eq!(
            ErrorCodes::from(String::from("configuration_error")),
            ErrorCodes::ConfigurationError
        );
        assert_eq!(
            ErrorCodes::from(String::from("url_parse_error")),
            ErrorCodes::UrlParseError
        );
        assert_eq!(
            ErrorCodes::from(String::from("other_error")),
            ErrorCodes::OtherError
        );
    }
}
