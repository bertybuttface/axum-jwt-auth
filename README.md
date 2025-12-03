# axum-jwt-auth

[![Rust](https://github.com/cmackenzie1/axum-jwt-auth/actions/workflows/rust.yml/badge.svg)](https://github.com/cmackenzie1/axum-jwt-auth/actions/workflows/rust.yml)
[![Crates.io Version](https://img.shields.io/crates/v/axum-jwt-auth)](https://crates.io/crates/axum-jwt-auth)
[![docs.rs](https://img.shields.io/docsrs/axum-jwt-auth)](https://docs.rs/axum-jwt-auth)

JWT authentication middleware for Axum. Supports local keys and remote JWKS with automatic caching and refresh.

## Installation

```bash
cargo add axum-jwt-auth
```

## Quick Start

```rust
use axum::{routing::get, Router};
use axum_jwt_auth::{Claims, JwtDecoderState, LocalDecoder};
use jsonwebtoken::{DecodingKey, Algorithm, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct MyClaims {
    sub: String,
    exp: usize,
}

async fn protected(user: Claims<MyClaims>) -> String {
    format!("Hello, {}!", user.claims.sub)
}

#[tokio::main]
async fn main() {
    let keys = vec![DecodingKey::from_secret(b"secret")];
    let decoder = LocalDecoder::builder()
        .keys(keys)
        .validation(Validation::new(Algorithm::HS256))
        .build()
        .unwrap();

    let state = JwtDecoderState {
        decoder: Arc::new(decoder),
    };

    let app = Router::new()
        .route("/protected", get(protected))
        .with_state(state);

    // Server will expect: Authorization: Bearer <jwt>
}
```

## Features

- **Local validation**: Validate JWTs with local RSA/HMAC keys
- **Remote JWKS**: Automatic fetching, caching, and refresh of remote JWKS endpoints
- **Flexible token extraction**: Bearer tokens (default), custom headers or cookies
- **Type-safe claims**: Strongly-typed claims via generic extractors
- **Axum integration**: Drop-in extractor for route handlers

## Remote JWKS

Validate JWTs using remote JWKS endpoints with automatic caching and refresh:

```rust
use axum_jwt_auth::{Claims, JwtDecoderState, RemoteJwksDecoder};
use jsonwebtoken::{Algorithm, Validation};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["your-audience"]);
    validation.set_issuer(&["your-issuer"]);

    let decoder = RemoteJwksDecoder::builder()
        .jwks_url("https://your-auth-provider.com/.well-known/jwks.json".to_string())
        .validation(validation)
        .build()
        .unwrap();
    let decoder = Arc::new(decoder);

    // Initialize: fetch keys immediately and start background refresh task
    let shutdown_token = decoder.initialize().await.expect("Failed to initialize JWKS decoder");

    let state = JwtDecoderState { decoder };
    let app = Router::new()
        .route("/protected", get(protected))
        .with_state(state);

    // Later, during application shutdown:
    shutdown_token.cancel();
}
```

The remote decoder:
- Fetches JWKS on initialization
- Automatically refreshes keys in the background (default: every hour)
- Caches keys for fast lookup by `kid` (key ID)
- Includes retry logic with configurable attempts and backoff
- Supports graceful shutdown via `CancellationToken`

## Custom Token Extractors

Extract tokens from custom headers or cookies:

```rust
use axum_jwt_auth::{define_header_extractor, define_cookie_extractor};

define_header_extractor!(XAuthToken, "x-auth-token");
define_cookie_extractor!(AuthCookie, "auth_token");

async fn header_auth(user: Claims<MyClaims, HeaderTokenExtractor<XAuthToken>>) { }
async fn cookie_auth(user: Claims<MyClaims, CookieTokenExtractor<AuthCookie>>) { }
```

## TLS and Crypto Backend Configuration

By default, `axum-jwt-auth` uses `rustls-tls` with the `rust_crypto` backend for compatibility. You can configure different backends via Cargo features:

```toml
# Default: uses rust_crypto for JWT, ring for TLS
axum-jwt-auth = "0.6"

# Recommended for new projects: uses aws-lc-rs for both JWT and TLS (faster, no dual compilation)
axum-jwt-auth = { version = "0.6", default-features = false, features = ["rustls-tls-aws-lc-rs"] }

# Explicitly use ring backend for both JWT and TLS
axum-jwt-auth = { version = "0.6", default-features = false, features = ["rustls-tls-ring"] }

# Use platform-native TLS with rust_crypto for JWT
axum-jwt-auth = { version = "0.6", default-features = false, features = ["native-tls"] }
```

**Why choose `rustls-tls-aws-lc-rs`?**
- Uses `aws-lc-rs` for both JWT validation (via jsonwebtoken) and TLS (via reqwest/rustls)
- Avoids compiling multiple crypto backends (reduces build time by ~1-2 minutes)
- Better compatibility with other crates that use `aws-lc-rs` as default
- Recommended by the Rustls project for new applications

**Feature matrix:**

| Feature | JWT Crypto | TLS Backend | Use Case |
|---------|-----------|-------------|----------|
| `rustls-tls` (default) | `rust_crypto` | `ring` | Maximum compatibility |
| `rustls-tls-aws-lc-rs` | `aws-lc-rs` | `aws-lc-rs` | Recommended for new projects |
| `rustls-tls-ring` | `ring` | `ring` | Explicit ring usage |
| `native-tls` | `rust_crypto` | platform | Use OS TLS stack |

## Examples

See the [examples](./examples/) directory for complete working examples:

- [**local**](./examples/local/) - Local RSA key validation
- [**remote**](./examples/remote/) - Remote JWKS with caching and retry logic
- [**cloudflare**](./examples/cloudflare/) - Cloudflare Access JWT validation

## License

MIT - see [LICENSE](LICENSE) for details.
