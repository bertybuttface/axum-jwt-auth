use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use derive_builder::Builder;
use jsonwebtoken::{jwk::JwkSet, DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;
use tokio::sync::Notify;
use tracing::{debug, error, info, trace, warn}; // Ensure tracing macros are imported

use crate::{Error, JwtDecoder};

const DEFAULT_CACHE_DURATION: std::time::Duration = std::time::Duration::from_secs(60 * 60); // 1 hour
const DEFAULT_RETRY_COUNT: usize = 3; // 3 attempts
const DEFAULT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1); // 1 second

/// Configuration for the Remote JWKS Decoder behavior.
#[derive(Debug, Clone, Builder)]
#[builder(setter(into))] // Allow into() for builder methods
pub struct RemoteJwksDecoderConfig {
    /// How long to cache the JWKS keys for
    #[builder(default = "DEFAULT_CACHE_DURATION")]
    pub cache_duration: std::time::Duration,
    /// How many times to retry fetching the JWKS keys if it fails
    #[builder(default = "DEFAULT_RETRY_COUNT")]
    pub retry_count: usize,
    /// How long to wait before retrying fetching the JWKS keys
    #[builder(default = "DEFAULT_BACKOFF")]
    pub backoff: std::time::Duration,
}

// Implement Default for easier configuration building
impl Default for RemoteJwksDecoderConfig {
    fn default() -> Self {
        trace!("Creating default RemoteJwksDecoderConfig"); // Add trace
        Self {
            cache_duration: DEFAULT_CACHE_DURATION,
            retry_count: DEFAULT_RETRY_COUNT,
            backoff: DEFAULT_BACKOFF,
        }
    }
}

impl RemoteJwksDecoderConfig {
    /// Creates a new [`RemoteJwksDecoderConfigBuilder`].
    ///
    /// This is a convenience method to create a builder for the config.
    pub fn builder() -> RemoteJwksDecoderConfigBuilder {
        trace!("Creating RemoteJwksDecoderConfigBuilder"); // Add trace
        RemoteJwksDecoderConfigBuilder::default()
    }
}

/// Remote JWKS decoder.
/// It fetches the JWKS from the given URL and caches it for the given duration.
/// It uses the cached JWKS to decode the JWT tokens.
#[derive(Clone, Builder)]
#[builder(setter(into))] // Allow into() for builder methods
pub struct RemoteJwksDecoder {
    /// The URL to fetch the JWKS from
    jwks_url: String,
    /// The configuration for the decoder's refresh behavior.
    #[builder(default = "RemoteJwksDecoderConfig::default()")]
    config: RemoteJwksDecoderConfig,
    /// The thread-safe cache for storing decoded JWKS keys (kid -> DecodingKey).
    #[builder(default = "Arc::new(DashMap::new())")]
    keys_cache: Arc<DashMap<String, DecodingKey>>,
    /// The validation settings for the JWT tokens
    validation: Validation,
    /// The HTTP client to use for fetching the JWKS
    #[builder(default = "reqwest::Client::new()")]
    client: reqwest::Client,
    /// The initialized flag
    #[builder(default = "Arc::new(Notify::new())")]
    initialized: Arc<Notify>,
}

impl RemoteJwksDecoder {
    /// Creates a new [`RemoteJwksDecoder`] with the given JWKS URL and default configuration.
    /// Note: Validation settings must be added via the builder.
    ///
    /// # Deprecated
    /// This method is less flexible as it requires manual setting of validation later.
    /// Prefer using `RemoteJwksDecoder::builder()` for complete setup.
    #[deprecated(
        since = "0.5.0", // Adjust version as needed if released
        note = "Prefer using RemoteJwksDecoder::builder() which requires Validation"
    )]
    pub fn new(jwks_url: String) -> Result<Self, Error> {
        trace!(%jwks_url, "Creating RemoteJwksDecoder with default config (using deprecated `new`)"); // Add trace
        // Note: This will fail at build time now unless the builder is modified
        // as 'validation' is not provided a default. Using builder directly is better.
        RemoteJwksDecoderBuilder::default()
            .jwks_url(jwks_url)
            // .validation(...) // Missing validation setup here!
            .build()
            .map_err(|e| Error::Configuration(e.to_string()))
    }

    /// Creates a new [`RemoteJwksDecoderBuilder`].
    ///
    /// This is a convenience method to create a builder for the decoder.
    pub fn builder() -> RemoteJwksDecoderBuilder {
        trace!("Creating RemoteJwksDecoderBuilder via builder() method"); // Add trace
        RemoteJwksDecoderBuilder::default()
    }

    /// Refreshes the JWKS cache once by fetching from the URL.
    /// Handles HTTP errors, deserialization errors, and key conversion errors.
    async fn refresh_keys_once(&self) -> Result<(), Error> {
        trace!(jwks_url = %self.jwks_url, "Attempting to fetch JWKS");
        let response_result = self.client.get(&self.jwks_url).send().await;

        let response = match response_result {
            Ok(resp) => {
                let status = resp.status(); // Get status code early
                trace!(jwks_url = %self.jwks_url, %status, "Received response for JWKS");
                // Use error_for_status() to check for non-success status codes
                match resp.error_for_status() {
                    Ok(success_resp) => {
                        trace!(jwks_url = %self.jwks_url, %status, "JWKS fetch status successful (2xx)");
                        success_resp // Pass the successful response onwards
                    }
                    Err(status_error) => {
                        // status_error is a reqwest::Error containing status and URL
                        error!(jwks_url = %self.jwks_url, error = %status_error, "JWKS fetch failed with non-success status");
                        // Logging the body is difficult here as error_for_status consumes the response
                        return Err(crate::Error::Reqwest(status_error)); // Wrap the reqwest::Error
                    }
                }
            }
            Err(e) => {
                // This is for connection/timeout errors etc.
                error!(jwks_url = %self.jwks_url, error = %e, "JWKS fetch HTTP request failed");
                return Err(crate::Error::Reqwest(e));
            }
        };

        // --- Body Reading and Deserialization ---
        trace!(jwks_url = %self.jwks_url, "Attempting to read JWKS response body");
        let bytes = match response.bytes().await {
            Ok(b) => {
                trace!(jwks_url = %self.jwks_url, byte_count = b.len(), "Successfully read JWKS response body");
                b
            }
            Err(e) => {
                error!(jwks_url = %self.jwks_url, error = %e, "Failed to read JWKS response body bytes");
                return Err(crate::Error::Reqwest(e));
            }
        };

        trace!(jwks_url = %self.jwks_url, "Attempting to deserialize JWKS JSON");
        let jwks: JwkSet = match serde_json::from_slice::<JwkSet>(&bytes) {
            Ok(set) => {
                trace!(key_count = set.keys.len(), "Successfully deserialized JWKS JSON");
                set
            }
            Err(e) => {
                error!(error = %e, "Failed to deserialize JWKS JSON");
                let body_snippet = String::from_utf8_lossy(&bytes[..bytes.len().min(500)]);
                debug!(response_body_snippet = %body_snippet, "Raw response body snippet");
                let jwt_error_kind = jsonwebtoken::errors::ErrorKind::Json(Arc::new(e));
                return Err(crate::Error::Jwt(jsonwebtoken::errors::Error::from(
                    jwt_error_kind,
                )));
            }
        };

        // --- Key Processing ---
        trace!(key_count = jwks.keys.len(), "Parsing keys from JWKS");
        let mut new_keys = Vec::new();
        for jwk in jwks.keys.iter() {
            let kid = jwk.common.key_id.clone().unwrap_or_default(); // Use default "" if missing

            if kid.is_empty() {
                warn!(jwk = ?jwk, "Skipping key in JWKS because it has no 'kid'.");
                continue;
            }

            trace!(%kid, jwk_alg = ?jwk.common.key_algorithm, "Processing JWK");

            // Optional: Check algorithm specified *in the JWK* against validation rules
            if let Some(ref key_alg) = jwk.common.key_algorithm {
                 let alg_str = key_alg.to_string();
                 // Ensure the key's specified algorithm is one we allow in general validation
                 if !self.validation.algorithms.iter().any(|v_alg| format!("{:?}", v_alg) == alg_str) {
                     warn!(%kid, key_alg = ?key_alg, allowed_algs = ?self.validation.algorithms, "Skipping key due to mismatched algorithm specified in JWK");
                     continue;
                 }
                 trace!(%kid, %alg_str, "JWK algorithm matches allowed validation algorithms");
            } else {
                 trace!(%kid, "JWK has no 'alg' field; validation will rely on token header and main validation algorithms");
            }

            trace!(%kid, "Attempting to convert JWK to DecodingKey");
            match DecodingKey::from_jwk(jwk) {
                Ok(decoding_key) => {
                    trace!(%kid, "Successfully converted JWK to DecodingKey");
                    new_keys.push((kid, decoding_key)); // Store kid along with the key
                }
                Err(e) => {
                    error!(%kid, error = %e, jwk = ?jwk, "Failed to convert JWK to DecodingKey");
                    // Continue processing other keys, log this specific failure
                }
            }
        }

        // Log warnings if no usable keys were found
        if new_keys.is_empty() {
             if jwks.keys.is_empty() {
                 warn!("Fetched JWKS contained no keys.");
             } else {
                 warn!("Processed JWKS containing {} keys, but none were successfully converted to DecodingKey. Check algorithms and key formats.", jwks.keys.len());
             }
             // Depending on requirements, an error could be returned here if *no* keys are ever usable.
             // For now, we allow continuing, hoping a future refresh might succeed.
             // return Err(Error::Configuration("No usable keys found in JWKS".into()));
        }

        // --- Cache Update ---
        trace!(current_cache_size = self.keys_cache.len(), "Clearing existing key cache");
        self.keys_cache.clear(); // Clear cache before loading new keys
        trace!(new_key_count = new_keys.len(), "Inserting processed keys into cache");
        for (kid, key) in new_keys {
            trace!(%kid, "Inserting key into cache");
            self.keys_cache.insert(kid, key); // Insert successfully processed keys
        }
        trace!(final_cache_size = self.keys_cache.len(), "Finished updating key cache");

        // --- Notify Initialized ---
        // Notify waiters *after* keys have been potentially updated in the cache.
        // This signals that at least one attempt (successful or not) to load keys has finished.
        trace!("Notifying waiters that initialization/refresh cycle is complete");
        self.initialized.notify_waiters();

        info!("JWKS keys refreshed successfully ({} keys loaded into cache)", self.keys_cache.len());
        Ok(())
    }

    /// Refreshes the JWKS cache, retrying on failure according to config.
    async fn refresh_keys(&self) -> Result<(), Error> {
        trace!("`refresh_keys` called"); // Add trace
        let max_attempts = self.config.retry_count;
        let mut attempt = 0;
        let mut last_error: Option<Error> = None;

        while attempt < max_attempts {
            let current_attempt = attempt + 1; // 1-based for logging
            trace!(attempt = current_attempt, max_attempts, "Attempting JWKS refresh via refresh_keys_once");
            match self.refresh_keys_once().await {
                Ok(_) => {
                    trace!(attempt = current_attempt, "JWKS refresh successful");
                    return Ok(());
                }
                Err(e) => {
                    warn!(attempt = current_attempt, max_attempts, error = %e, "JWKS refresh attempt failed");
                    last_error = Some(e); // Store the error from this attempt
                    attempt += 1; // Increment attempt counter
                    if attempt < max_attempts {
                        let backoff_duration = self.config.backoff; // Using fixed backoff from config
                        trace!(attempt = current_attempt, max_attempts, duration = ?backoff_duration, "Sleeping before next refresh attempt");
                        tokio::time::sleep(backoff_duration).await;
                    } else {
                         trace!(attempt = current_attempt, max_attempts, "Reached max refresh attempts");
                    }
                }
            }
        }

        // If loop finishes, all attempts failed
        error!(max_attempts, "Failed to refresh JWKS after all attempts.");
        // Return the last error encountered, wrapped in a specific JwksRefresh error
        Err(Error::JwksRefresh {
            message: "Failed to refresh JWKS after multiple attempts".to_string(),
            retry_count: max_attempts,
            // Ensure the source error is boxed correctly
            source: last_error.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        })
    }

    /// Runs indefinitely, refreshing the JWKS cache periodically based on `cache_duration`.
    /// Handles errors during refresh attempts according to the retry policy.
    pub async fn refresh_keys_periodically(&self) {
        trace!("`refresh_keys_periodically` task started"); // Add trace

        // Perform an initial refresh immediately when this task starts.
        info!("Performing initial JWKS refresh within periodic task...");
        if let Err(err) = self.refresh_keys().await {
            // Log the error, but the task continues. Initialization might still be blocked
            // if this very first attempt fails completely, as `notify_waiters` wouldn't be called.
            error!(error = ?err, "Initial JWKS refresh failed within periodic task");
        } else {
            info!("Initial JWKS refresh within periodic task successful.");
        }

        // Now enter the periodic refresh loop
        loop {
            let sleep_duration = self.config.cache_duration;
            trace!(duration = ?sleep_duration, "Sleeping until next scheduled periodic JWKS refresh");
            tokio::time::sleep(sleep_duration).await;

            trace!("Woke up for periodic refresh"); // Add trace
            info!("Performing periodic JWKS refresh");
            if let Err(err) = self.refresh_keys().await {
                // Log the error after retries, but continue the loop
                error!(error = ?err, retry_count = self.config.retry_count, "Periodic JWKS refresh failed after multiple attempts");
            } else {
                trace!("Periodic JWKS refresh successful"); // Already logged info in refresh_keys_once
            }
        }
        // This line is typically unreachable in an infinite loop
        // error!("`refresh_keys_periodically` task unexpectedly exited!");
    }

    /// Ensures keys are available before proceeding
    async fn ensure_initialized(&self) {
        self.initialized.notified().await;
    }
}

#[async_trait]
impl<T> JwtDecoder<T> for RemoteJwksDecoder
where
    T: for<'de> DeserializeOwned,
{
    /// Decodes a JWT token string using the cached JWKS keys.
    /// Waits for initial key load if necessary.
    async fn decode(&self, token: &str) -> Result<TokenData<T>, Error> {

        trace!("`decode` called");
        self.ensure_initialized().await; // <--- COMMENT THIS OUT TEMPORARILY
        trace!("Decoder initialized check passed. Attempting to decode token header."); // Keep commented if above is commented

        // --- Start decoding immediately ---
        trace!("Attempting to decode token header.");

        let header = match jsonwebtoken::decode_header(token) {
            Ok(h) => {
                trace!(header = ?h, "Successfully decoded JWT header");
                h
            }
            Err(e) => {
                error!(error = %e, "Failed to decode JWT header");
                // Map the header decoding error before returning
                return Err(Error::Jwt(e));
            }
        };

        let target_kid = header.kid; // Option<String>
        trace!(kid = ?target_kid, "Extracted 'kid' from token header");

        match target_kid {
            Some(ref kid) if !kid.is_empty() => {
                // Kid is present and not empty
                trace!(%kid, "Attempting to find key in cache");
                if let Some(key_ref) = self.keys_cache.get(kid) {
                    // Key found in cache, dereference the Ref<...> to get &DecodingKey
                    let key = key_ref.value();
                    trace!(%kid, "Key found in cache. Attempting token validation.");
                    let validation_result = jsonwebtoken::decode::<T>(token, key, &self.validation);

                    match validation_result {
                        Ok(token_data) => {
                            trace!(%kid, "Token validation successful");
                            Ok(token_data)
                        }
                        Err(e) => {
                            let error_kind = format!("{:?}", e.kind());
                            error!(%kid, error = %e, error_kind = %error_kind, "Token validation failed using cached key");
                            Err(Error::Jwt(e)) // Map the validation error
                        }
                    }
                } else {
                    // Key specified in token but not found in our cache
                    error!(%kid, cache_size = self.keys_cache.len(), "Key specified in token not found in the cached JWKS keys");
                    Err(Error::KeyNotFound(Some(kid.clone())))
                }
            }
            Some(_) => { // Kid was present but empty ("")
                 error!("Token header contains an empty 'kid', cannot perform lookup.");
                 Err(Error::KeyNotFound(Some("".to_string()))) // Indicate empty kid was the issue
            }
            None => {
                // No kid in token header
                error!("Token header does not contain a 'kid' (Key ID), cannot select key from JWKS.");
                Err(Error::KeyNotFound(None))
            }
        }
    }
}
