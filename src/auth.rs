use std::{
    fs::{self, File},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use oauth2::{
    basic::{BasicClient, BasicTokenType},
    AccessToken, AsyncHttpClient, ClientId, ClientSecret, DeviceAuthorizationUrl,
    EmptyExtraTokenFields, HttpRequest, HttpResponse, RefreshToken, Scope,
    StandardDeviceAuthorizationResponse, StandardTokenResponse, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ErrorCodes, SiteMonitorError, SiteMonitorResult},
    interface::Interface,
};

pub async fn request_token<I: Interface + Clone + Send>(
    interface: I,
) -> SiteMonitorResult<AccessToken> {
    let config = interface.get_config();
    let scopes: Vec<Scope> = config
        .scopes
        .iter()
        .map(|s| Scope::new(s.to_string()))
        .collect();

    loop {
        let result = device_code_flow(
            &config.client_id,
            None,
            config.device_auth_url.to_owned(),
            config.token_url.to_owned(),
            scopes.to_owned(),
            interface.to_owned(),
        )
        .await;
        match result {
            Ok(result) => return Ok(result),
            Err(err) => {
                if err.error_code == ErrorCodes::InvalidGrant
                    || err.error_code == ErrorCodes::NoToken
                    || err.error_code == ErrorCodes::ExpiredToken
                {
                    log::error!("{err} Please login again!");
                } else {
                    return Err(err);
                }
            }
        }
    }
}

async fn device_code_flow<I: Interface + Clone + Send>(
    client_id: &str,
    client_secret: Option<ClientSecret>,
    device_auth_endpoint: DeviceAuthorizationUrl,
    token_endpoint: TokenUrl,
    scopes: Vec<Scope>,
    interface: I,
) -> SiteMonitorResult<AccessToken> {
    let oauth2_cloud = DeviceCodeFlow::new(
        ClientId::new(client_id.to_string()),
        client_secret,
        device_auth_endpoint,
        token_endpoint,
        interface.clone(),
    );

    let directory = interface.get_token_path();

    let token_file = PathBuf::from(format!("{}_device_code_flow.json", client_id));
    let mut token_keeper = TokenKeeper::new(directory.to_path_buf());

    // If there is no exsting token, get it from the cloud
    if let Err(err) = token_keeper.read(&token_file) {
        log::error!("[{:?}]: {err}", token_file);
        let device_auth_response = oauth2_cloud.request_device_code(scopes).await?;

        log::info!(
            "Login Here: {}",
            &device_auth_response.verification_uri().as_str(),
        );
        log::info!(
            "Device Code: {}",
            &device_auth_response.user_code().secret()
        );

        let token = oauth2_cloud.poll_access_token(device_auth_response).await?;
        token_keeper = TokenKeeper::from(token);
        token_keeper.set_directory(directory.to_path_buf());

        token_keeper.save(&token_file)?;
    } else {
        token_keeper = oauth2_cloud
            .get_access_token(&directory, &token_file)
            .await?;
    }
    log::info!("Access granted!");
    Ok(token_keeper.access_token)
}

pub struct DeviceCodeFlow<I>
where
    I: Interface,
{
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    device_auth_endpoint: DeviceAuthorizationUrl,
    token_endpoint: TokenUrl,
    curl_client: OAuth2Client<I>,
}

impl<I> DeviceCodeFlow<I>
where
    I: Interface + Clone + Send,
{
    async fn request_device_code(
        &self,
        scopes: Vec<Scope>,
    ) -> SiteMonitorResult<StandardDeviceAuthorizationResponse> {
        let mut client = BasicClient::new(self.client_id.to_owned());
        if let Some(client_secret) = self.client_secret.to_owned() {
            client = client.set_client_secret(client_secret);
        }
        let device_auth_response = client
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_token_uri(self.token_endpoint.to_owned())
            .set_device_authorization_url(self.device_auth_endpoint.to_owned())
            .exchange_device_code()
            .add_scopes(scopes)
            .request_async(&self.curl_client)
            .await?;

        Ok(device_auth_response)
    }
    async fn poll_access_token(
        &self,
        device_auth_response: StandardDeviceAuthorizationResponse,
    ) -> SiteMonitorResult<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
        let mut client = BasicClient::new(self.client_id.to_owned());
        if let Some(client_secret) = self.client_secret.to_owned() {
            client = client.set_client_secret(client_secret);
        }
        let token_result = client
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_token_uri(self.token_endpoint.to_owned())
            .exchange_device_access_token(&device_auth_response)
            .request_async(&self.curl_client, tokio::time::sleep, None)
            .await?;
        Ok(token_result)
    }

    async fn get_access_token(
        &self,
        file_directory: &Path,
        file_name: &Path,
    ) -> SiteMonitorResult<TokenKeeper> {
        let mut token_keeper = TokenKeeper::new(file_directory.to_path_buf());
        token_keeper.read(file_name)?;

        if token_keeper.has_access_token_expired() {
            match token_keeper.refresh_token {
                Some(ref_token) => {
                    log::info!("Renewing access...");
                    let mut client = BasicClient::new(self.client_id.to_owned());
                    if let Some(client_secret) = self.client_secret.to_owned() {
                        client = client.set_client_secret(client_secret);
                    }
                    let response = client
                        .set_auth_type(oauth2::AuthType::RequestBody)
                        .set_token_uri(self.token_endpoint.to_owned())
                        .exchange_refresh_token(&ref_token)
                        .request_async(&self.curl_client)
                        .await;

                    match response {
                        Ok(res) => {
                            token_keeper = TokenKeeper::from(res);
                            token_keeper.set_directory(file_directory.to_path_buf());
                            token_keeper.save(file_name)?;
                            Ok(token_keeper)
                        }
                        Err(e) => {
                            let error = SiteMonitorError::from(e);
                            if error.error_code == ErrorCodes::InvalidGrant {
                                let file = TokenKeeper::new(file_directory.to_path_buf());
                                if let Err(e) = file.delete(file_name) {
                                    log::error!("{:?}", e);
                                }
                            }
                            Err(error)
                        }
                    }
                }
                None => {
                    log::info!("Please login again.");
                    token_keeper.delete(file_name)?;
                    Err(SiteMonitorError::new(
                        ErrorCodes::NoToken,
                        "There is no refresh token.".into(),
                    ))
                }
            }
        } else {
            Ok(token_keeper)
        }
    }

    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        device_auth_endpoint: DeviceAuthorizationUrl,
        token_endpoint: TokenUrl,
        interface: I,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            device_auth_endpoint,
            token_endpoint,
            curl_client: OAuth2Client::new(interface),
        }
    }
}

struct OAuth2Client<I>
where
    I: Interface,
{
    interface: I,
}

impl<I> OAuth2Client<I>
where
    I: Interface,
{
    pub fn new(interface: I) -> Self {
        Self { interface }
    }
}

impl<'c, I> AsyncHttpClient<'c> for OAuth2Client<I>
where
    I: Interface + Clone + Send,
{
    type Error = SiteMonitorError;

    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        let interface = self.interface.clone();
        Box::pin(async move { interface.oauth2_curl_perform(request).await })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenKeeper {
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    pub scopes: Option<Vec<String>>,
    pub expires_in: Option<Duration>,
    pub token_receive_time: Duration,
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    pub file_directory: PathBuf,
}

impl TokenKeeper {
    pub fn new(file_directory: PathBuf) -> Self {
        Self {
            access_token: AccessToken::new(String::new()),
            refresh_token: None,
            scopes: None,
            expires_in: None,
            token_receive_time: Duration::new(0, 0),
            file_directory,
        }
    }

    pub fn set_directory(&mut self, file_directory: PathBuf) {
        self.file_directory = file_directory;
    }
    pub fn has_access_token_expired(&self) -> bool {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        if let Some(expires) = self.expires_in {
            (time_now - self.token_receive_time) >= expires
        } else {
            true
        }
    }

    pub fn read(&mut self, file_name: &Path) -> SiteMonitorResult<()> {
        let temp_dir = self.file_directory.clone();
        let input_path = self.file_directory.join(file_name);
        let text = std::fs::read_to_string(input_path)?;

        *self = serde_json::from_str::<TokenKeeper>(&text)?;
        self.set_directory(temp_dir);
        Ok(())
    }

    pub fn save(&self, file_name: &Path) -> SiteMonitorResult<()> {
        let input_path = self.file_directory.join(file_name);
        let json = serde_json::to_string(self)?;

        fs::create_dir_all(self.file_directory.as_path())?;

        let mut file = File::create(input_path)?;

        file.write_all(json.as_bytes())?;

        Ok(())
    }

    pub fn delete(&self, file_name: &Path) -> SiteMonitorResult<()> {
        let input_path = self.file_directory.join(file_name);
        Ok(fs::remove_file(input_path)?)
    }
}

impl From<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> for TokenKeeper {
    fn from(
        token_response: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    ) -> TokenKeeper {
        let refresh_token = token_response
            .refresh_token()
            .map(|ref_tok| ref_tok.to_owned());

        let scopes = token_response
            .scopes()
            .map(|scope| scope.iter().map(|e| e.to_string()).collect());

        Self {
            access_token: token_response.access_token().to_owned(),
            refresh_token,
            scopes,
            expires_in: token_response.expires_in(),
            token_receive_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards"),
            file_directory: PathBuf::new(),
        }
    }
}
