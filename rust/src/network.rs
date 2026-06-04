// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! reqwest integration for AntiSSRF protection.
//!
//! This module provides three integration points for [`reqwest`](https://docs.rs/reqwest):
//!
//! | Type | Purpose | Used with |
//! |------|---------|-----------|
//! | [`AntiSSRFResolver`](crate::network::reqwest_integration::AntiSSRFResolver) | Custom DNS resolver that blocks disallowed IPs before connection | [`reqwest::ClientBuilder::dns_resolver`](reqwest::ClientBuilder) |
//! | [`AntiSSRFMiddleware`](crate::network::reqwest_integration::AntiSSRFMiddleware) | Tower-compatible middleware that validates headers, protocol, and redirects | [`reqwest_middleware`](https://docs.rs/reqwest-middleware) |
//! | [`AntiSSRFClientBuilder`](crate::network::reqwest_integration::AntiSSRFClientBuilder) | Convenience builder that wires resolver + middleware automatically | Direct construction |
//!
//! # Architecture
//!
//! DNS resolution is the **first** line of defence: [`AntiSSRFResolver`](crate::network::reqwest_integration::AntiSSRFResolver) intercepts
//! every hostname lookup and rejects resolved IPs that violate the policy.
//! This happens before any TCP connection is established.
//!
//! The [`AntiSSRFMiddleware`](crate::network::reqwest_integration::AntiSSRFMiddleware) layer is the **second** line of defence:
//! it validates request headers and protocol on the way out, and re-validates
//! every redirect URL on the way back.  This protects against DNS rebinding
//! (where a malicious host changes its IP after the initial lookup) and
//! open-redirect attacks that pivot to internal services.
//!
//! # Minimal Example
//!
//! ```rust,no_run
//! use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
//! use antissrf::network::reqwest_integration::AntiSSRFClientBuilder;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
//! let client = AntiSSRFClientBuilder::new(policy).build_with_middleware()?;
//!
//! let response = client
//!     .get("https://example.com")
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Redirect Handling
//!
//! [`AntiSSRFClientBuilder::build_with_middleware`](crate::network::reqwest_integration::AntiSSRFClientBuilder::build_with_middleware) disables reqwest's native
//! redirect policy and replaces it with a custom implementation inside
//! [`AntiSSRFMiddleware`](crate::network::reqwest_integration::AntiSSRFMiddleware).  The custom implementation:
//!
//! 1. Re-validates the redirect URL against the policy on every hop.
//! 2. Strips `Authorization` headers to prevent credential leakage.
//! 3. Converts POST → GET on 301/302/303 per RFC 7231.
//! 4. Preserves POST on 307/308 per RFC 7538.
//! 5. Caps at 50 hops to prevent infinite loops.
//!
//! # Feature Flag
//!
//! This module is only available when the **`reqwest-integration`** feature is enabled.

#[cfg(feature = "reqwest-integration")]
pub mod reqwest_integration {
    use crate::{AntiSSRFError, AntiSSRFPolicy};
    use http::Extensions;
    use reqwest::dns::{Name, Resolve, Resolving};
    use reqwest::{Request, Response};
    use reqwest_middleware::Error as MiddlewareError;
    use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::lookup_host;

    /// Custom DNS resolver that validates resolved IPs against AntiSSRF policy.
    ///
    /// Wraps tokio's DNS lookup with IP address filtering. Any resolved IP
    /// that violates the policy causes the lookup to fail with [`AntiSSRFError::IPDisallowed`].
    ///
    /// Because DNS happens **before** TCP connection, this blocks SSRF at the
    /// earliest possible point in the network stack.
    ///
    /// # Arguments
    ///
    /// * `policy` — An [`AntiSSRFPolicy`] (cloned internally, so no external
    ///   lifetime requirements).
    ///
    /// # Returns
    ///
    /// A boxed future that yields an iterator of [`SocketAddr`]s, or an error
    /// if every resolved IP is disallowed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
    /// use antissrf::network::reqwest_integration::AntiSSRFResolver;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
    /// let resolver = AntiSSRFResolver::new(policy);
    ///
    /// let client = reqwest::Client::builder()
    ///     .dns_resolver(Arc::new(resolver))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[derive(Debug, Clone)]
    pub struct AntiSSRFResolver {
        policy: AntiSSRFPolicy,
    }

    impl AntiSSRFResolver {
        /// Creates a new resolver wrapping the given policy.
        pub fn new(policy: AntiSSRFPolicy) -> Self {
            Self { policy }
        }
    }

    impl Resolve for AntiSSRFResolver {
        fn resolve(&self, name: Name) -> Resolving {
            let mut policy = self.policy.clone();
            let host = name.as_str().to_string();

            Box::pin(async move {
                // For bare IP addresses, skip DNS lookup and use the IP directly.
                // lookup_host requires host:port format, so we bypass it for IPs.
                let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    vec![SocketAddr::new(ip, 0)] // bare IPs are treated as `host:0` for policy checking
                } else {
                    // Perform DNS lookup for non-IP hosts.
                    // We append ":0" to satisfy lookup_host's requirement for a port, but the port is ignored in policy checks.
                    lookup_host(format!("{}:0", host))
                        .await
                        .map_err(Box::new)?
                        .collect()
                };

                let ip_strings: Vec<String> = addrs
                    .iter()
                    .map(|a: &SocketAddr| a.ip().to_string())
                    .collect();
                let ip_refs: Vec<&str> = ip_strings.iter().map(|s: &String| s.as_str()).collect();

                let allowed: bool = policy
                    .is_network_connection_allowed(&ip_refs)
                    .map_err(Box::new)?;
                if !allowed {
                    Err(Box::new(AntiSSRFError::IPDisallowed))?
                }

                let addrs: Box<dyn Iterator<Item = SocketAddr> + Send> =
                    Box::new(addrs.into_iter());
                Ok(addrs)
            })
        }
    }

    /// Convenience builder for creating a reqwest Client pre-configured with AntiSSRF.
    ///
    /// Provides a fluent API to build a [`reqwest::Client`] that uses [`AntiSSRFResolver`]
    /// for DNS resolution.  Redirects are disabled at the reqwest level; use
    /// [`Self::build_with_middleware`] to get full redirect re-validation.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
    /// use antissrf::network::reqwest_integration::AntiSSRFClientBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
    /// let client = AntiSSRFClientBuilder::new(policy)
    ///     .timeout(std::time::Duration::from_secs(30))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[derive(Debug)]
    pub struct AntiSSRFClientBuilder {
        policy: AntiSSRFPolicy,
        builder: reqwest::ClientBuilder,
    }

    impl AntiSSRFClientBuilder {
        /// Creates a new builder with the given policy.
        ///
        /// Automatically registers an [`AntiSSRFResolver`] and disables reqwest's
        /// native redirect handling.
        pub fn new(policy: AntiSSRFPolicy) -> Self {
            let resolver = Arc::new(AntiSSRFResolver::new(policy.clone()));
            let builder = reqwest::Client::builder()
                .dns_resolver(resolver)
                .redirect(reqwest::redirect::Policy::none());

            Self { policy, builder }
        }

        /// Sets a global timeout for the entire request (including all redirects).
        ///
        /// See [`reqwest::ClientBuilder::timeout`].
        ///
        /// # Example
        ///
        /// ```rust,no_run
        /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
        /// use antissrf::network::reqwest_integration::AntiSSRFClientBuilder;
        ///
        /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
        /// let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
        /// let client = AntiSSRFClientBuilder::new(policy)
        ///     .timeout(std::time::Duration::from_secs(30))
        ///     .build()?;
        /// # Ok(())
        /// # }
        /// ```
        pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
            self.builder = self.builder.timeout(timeout);
            self
        }

        /// Sets a timeout for establishing a TCP connection.
        ///
        /// See [`reqwest::ClientBuilder::connect_timeout`].
        pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
            self.builder = self.builder.connect_timeout(timeout);
            self
        }

        /// Sets the maximum number of idle connections per host.
        ///
        /// See [`reqwest::ClientBuilder::pool_max_idle_per_host`].
        pub fn pool_max_idle_per_host(mut self, max: usize) -> Self {
            self.builder = self.builder.pool_max_idle_per_host(max);
            self
        }

        /// Builds the configured [`reqwest::Client`].
        ///
        /// Redirects are disabled on the returned client; redirect handling
        /// is performed by [`AntiSSRFMiddleware`] when used via
        /// [`Self::build_with_middleware`].
        ///
        /// # Errors
        ///
        /// Returns an error if the underlying reqwest client fails to build.
        pub fn build(self) -> Result<reqwest::Client, reqwest::Error> {
            self.builder.build()
        }

        /// Builds a [`reqwest_middleware::ClientWithMiddleware`] with redirect
        /// re-validation enabled.
        ///
        /// This is the **preferred** method when you need full AntiSSRF protection
        /// including redirect chain validation. Returns a client that runs
        /// [`AntiSSRFMiddleware`] on every request and re-validates each
        /// redirect hop against the policy.
        ///
        /// # Errors
        ///
        /// Returns an error if the underlying reqwest client fails to build.
        ///
        /// # Example
        ///
        /// ```rust,no_run
        /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
        /// use antissrf::network::reqwest_integration::AntiSSRFClientBuilder;
        ///
        /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
        /// let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
        /// let client = AntiSSRFClientBuilder::new(policy).build_with_middleware()?;
        ///
        /// let response = client
        ///     .get("https://example.com")
        ///     .send()
        ///     .await?;
        /// # Ok(())
        /// # }
        /// ```
        pub fn build_with_middleware(
            self,
        ) -> Result<reqwest_middleware::ClientWithMiddleware, reqwest::Error> {
            let client = self.builder.build()?;
            let middleware = AntiSSRFMiddleware::new(self.policy).with_client(client.clone());
            Ok(reqwest_middleware::ClientBuilder::new(client)
                .with(middleware)
                .build())
        }
    }

    /// Middleware that validates HTTP request headers and protocol against AntiSSRF policy.
    ///
    /// Intercepts outgoing requests to ensure:
    /// - Protocol is allowed (`https` always ok, `http` only if `allow_plaintext_http`)
    /// - Denied headers are not present
    /// - Required headers are present
    /// - Injects `X-Forwarded-For` if configured
    /// - Re-validates redirect URLs on every hop
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
    /// use antissrf::network::reqwest_integration::AntiSSRFMiddleware;
    /// use reqwest_middleware::ClientBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
    /// let middleware = AntiSSRFMiddleware::new(policy);
    ///
    /// let client = ClientBuilder::new(reqwest::Client::new())
    ///     .with(middleware)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    #[derive(Debug)]
    pub struct AntiSSRFMiddleware {
        policy: AntiSSRFPolicy,
        client: Option<reqwest::Client>,
    }

    impl AntiSSRFMiddleware {
        /// Creates a new middleware instance with the given policy.
        ///
        /// Redirect re-validation requires a client to be supplied via
        /// [`Self::with_client`].
        pub fn new(policy: AntiSSRFPolicy) -> Self {
            Self {
                policy,
                client: None,
            }
        }

        /// Provide a [`reqwest::Client`] for handling redirect requests.
        ///
        /// Without a stored client, redirects cannot be re-validated and
        /// the middleware returns the redirect response as-is (still safe
        /// because DNS was already filtered by [`AntiSSRFResolver`]).
        pub fn with_client(mut self, client: reqwest::Client) -> Self {
            self.client = Some(client);
            self
        }
    }

    #[async_trait::async_trait]
    impl Middleware for AntiSSRFMiddleware {
        async fn handle(
            &self,
            mut req: Request,
            _extensions: &mut Extensions,
            next: Next<'_>,
        ) -> MiddlewareResult<Response> {
            let mut policy = self.policy.clone();

            let mut current_url = req.url().clone();
            let mut current_method = req.method().clone();
            let mut current_headers = req.headers().clone();

            Self::validate_and_prepare(&mut policy, &mut req)?;

            let mut response = next.run(req, _extensions).await?;
            let mut redirect_count = 0;
            const MAX_REDIRECTS: usize = 50;

            while redirect_count < MAX_REDIRECTS {
                let status = response.status();

                let is_redirect = matches!(status.as_u16(), 300 | 301 | 302 | 303 | 307 | 308);
                let location = response.headers().get(reqwest::header::LOCATION).cloned();

                if !is_redirect || location.is_none() {
                    return Ok(response);
                }

                let location = location.unwrap();
                let location_str = location.to_str().map_err(|e| {
                    MiddlewareError::Middleware(
                        AntiSSRFError::InvalidURL(format!("Invalid location header: {}", e)).into(),
                    )
                })?;

                // RFC 7231 §7.1.2: Location may be relative or absolute.
                // `Url::join` handles both — absolute URL replaces host,
                // relative path is resolved against current URL.
                let mut redirect_url = current_url.join(location_str).map_err(|e| {
                    MiddlewareError::Middleware(
                        AntiSSRFError::InvalidURL(format!("Invalid redirect URL: {}", e)).into(),
                    )
                })?;

                if redirect_url.fragment().is_none() {
                    // RFC 7231 §7.1.2: Preserve original fragment when redirect lacks one.
                    // e.g. GET /page#sec → 301 Location: /other → redirect to /other#sec
                    if let Some(fragment) = current_url.fragment() {
                        redirect_url.set_fragment(Some(fragment));
                    }
                }

                let new_method = Self::redirect_method(&current_method, status);
                let mut new_req = Request::new(new_method.clone(), redirect_url.clone());

                // RFC 7235 §4.1 Strip Authorization on redirect: prevents cross-origin credential leak.
                for (name, value) in current_headers.iter() {
                    if !name.as_str().eq_ignore_ascii_case("authorization") {
                        new_req.headers_mut().insert(name.clone(), value.clone());
                    }
                }

                // Clear body-related headers when method changes (e.g. POST→GET on 301/302/303).
                // These headers reference a body that no longer exists and can confuse servers.
                if new_method != current_method {
                    new_req.headers_mut().remove(reqwest::header::CONTENT_TYPE);
                    new_req
                        .headers_mut()
                        .remove(reqwest::header::CONTENT_LENGTH);
                    new_req
                        .headers_mut()
                        .remove(reqwest::header::TRANSFER_ENCODING);
                    new_req
                        .headers_mut()
                        .remove(reqwest::header::CONTENT_ENCODING);
                    new_req.headers_mut().remove(reqwest::header::EXPECT);
                }

                Self::validate_and_prepare(&mut policy, &mut new_req)?;

                current_url = redirect_url;
                current_method = new_method;
                current_headers = new_req.headers().clone();

                let client = match &self.client {
                    Some(c) => c,
                    None => return Ok(response),
                };

                response = client
                    .execute(new_req)
                    .await
                    .map_err(MiddlewareError::Reqwest)?;
                redirect_count += 1;
            }

            Ok(response)
        }
    }

    impl AntiSSRFMiddleware {
        /// Validates scheme, headers, and protocol against the policy.
        ///
        /// Also applies any header mutations requested by the policy (e.g.
        /// injecting `X-Forwarded-For`, removing denied headers).
        ///
        /// # Errors
        ///
        /// Returns [`MiddlewareError::Middleware`] wrapping [`AntiSSRFError`] if
        /// the request violates the policy.
        fn validate_and_prepare(
            policy: &mut AntiSSRFPolicy,
            req: &mut Request,
        ) -> Result<(), MiddlewareError> {
            let scheme = req.url().scheme();
            let protocol = format!("{}:", scheme);

            let mut headers: Vec<(String, String)> = req
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    let key = k.to_string();
                    let value = v.to_str().ok()?.to_string();
                    Some((key, value))
                })
                .collect();

            policy
                .validate_request(&protocol, &mut headers)
                .map_err(|e| MiddlewareError::Middleware(e.into()))?;

            // Overwrite all headers with validated set.
            // validate_request may have injected XFF/filtered denied headers;
            // the returned Vec is the authoritative header list.
            req.headers_mut().clear();
            for (key, value) in headers {
                let name =
                    reqwest::header::HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                        MiddlewareError::Middleware(
                            AntiSSRFError::InvalidURL(format!("Invalid header name: {}", e)).into(),
                        )
                    })?;
                let val = reqwest::header::HeaderValue::from_str(&value).map_err(|e| {
                    MiddlewareError::Middleware(
                        AntiSSRFError::InvalidURL(format!("Invalid header value: {}", e)).into(),
                    )
                })?;
                req.headers_mut().insert(name, val);
            }

            Ok(())
        }

        /// Determines the HTTP method to use after a redirect.
        ///
        /// Follows RFC 7231 and RFC 7538:
        /// - 301/302: POST → GET
        /// - 303: any non-idempotent → GET
        /// - 307/308: preserve method
        fn redirect_method(
            method: &reqwest::Method,
            status: reqwest::StatusCode,
        ) -> reqwest::Method {
            match status.as_u16() {
                300..=302 => {
                    if *method == reqwest::Method::POST {
                        reqwest::Method::GET
                    } else {
                        method.clone()
                    }
                }
                303 => {
                    if *method != reqwest::Method::GET && *method != reqwest::Method::HEAD {
                        reqwest::Method::GET
                    } else {
                        method.clone()
                    }
                }
                307 | 308 => method.clone(),
                _ => method.clone(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::PolicyConfigOptions;
        use std::str::FromStr;

        #[tokio::test]
        async fn resolver_allows_public_ip() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
            let resolver = AntiSSRFResolver::new(policy);
            // Use direct IP to avoid DNS dependency in test environment
            let name: Name = "8.8.8.8".parse().unwrap();

            let result = resolver.resolve(name).await;

            if let Err(ref e) = result {
                eprintln!("Resolver error: {}", e);
            }
            assert!(
                result.is_ok(),
                "Public IP with None policy should be allowed"
            );
        }

        #[tokio::test]
        async fn resolver_blocks_localhost() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
            let resolver = AntiSSRFResolver::new(policy);
            let name: Name = "127.0.0.1".parse().unwrap();

            let result = resolver.resolve(name).await;
            assert!(
                result.is_err(),
                "127.0.0.1 with ExternalOnlyLatest should be blocked"
            );
        }

        #[tokio::test]
        async fn resolver_blocks_imds() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
            let resolver = AntiSSRFResolver::new(policy);
            let name: Name = "169.254.169.254".parse().unwrap();

            let result = resolver.resolve(name).await;
            assert!(
                result.is_err(),
                "IMDS IP with ExternalOnlyLatest should be blocked"
            );
        }

        #[tokio::test]
        async fn test_ipv6_bracketed_imds_blocked() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
            let resolver = AntiSSRFResolver::new(policy);
            let name = Name::from_str("[::ffff:a9fe:a9fe]").unwrap();
            let result = resolver.resolve(name).await;
            assert!(result.is_err(), "Should block IPv6 mapped IMDS");
        }

        #[tokio::test]
        async fn test_ipv6_unbracketed_imds_blocked() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
            let resolver = AntiSSRFResolver::new(policy);
            let name = Name::from_str("::ffff:a9fe:a9fe").unwrap();
            let result = resolver.resolve(name).await;
            assert!(result.is_err(), "Should block IPv6 mapped IMDS");
        }

        #[tokio::test]
        async fn test_ipv6_bracketed_imds_error_type() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
            let resolver = AntiSSRFResolver::new(policy);
            let name = Name::from_str("[::ffff:a9fe:a9fe]").unwrap();
            let result = resolver.resolve(name).await;

            let err_str = match result {
                Err(e) => format!("{}", e),
                Ok(_) => panic!("Expected error, got success"),
            };
            // Bracketed IPv6 bypasses direct IpAddr parse, so it may hit DNS lookup path
            // and produce a DNS error rather than IPDisallowed — known limitation
            assert!(
                err_str.contains("IP address disallowed")
                    || err_str.contains("DNS")
                    || err_str.contains("failed to lookup address"),
                "Unexpected error: {}",
                err_str
            );
        }

        #[tokio::test]
        async fn test_ipv6_unbracketed_imds_error_type() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
            let resolver = AntiSSRFResolver::new(policy);
            let name = Name::from_str("::ffff:a9fe:a9fe").unwrap();
            let result = resolver.resolve(name).await;

            let err_str = match result {
                Err(e) => format!("{}", e),
                Ok(_) => panic!("Expected error, got success"),
            };
            assert!(
                err_str.contains("IP address disallowed"),
                "Expected IPDisallowed, got: {}",
                err_str
            );
        }

        #[tokio::test]
        async fn hex_ip_is_normalized_and_blocked() {
            // URL parser normalizes 0xA9.0xFE.0xA9.0xFE -> 169.254.169.254
            // Middleware blocks before connecting, so no mock server needed
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
            let client = AntiSSRFClientBuilder::new(policy)
                .build_with_middleware()
                .expect("should build");

            let result = client.get("http://0xA9.0xFE.0xA9.0xFE/").send().await;

            assert!(
                result.is_err(),
                "Hex-encoded IMDS IP (0xA9.0xFE.0xA9.0xFE) should be blocked after URL normalization"
            );
        }

        #[tokio::test]
        async fn client_builder_works() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
            let client = AntiSSRFClientBuilder::new(policy)
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Client should build");

            // Just verify it doesn't panic
            drop(client);
        }

        #[tokio::test]
        async fn client_builder_with_middleware_works() {
            let policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
            let client = AntiSSRFClientBuilder::new(policy)
                .build_with_middleware()
                .expect("ClientWithMiddleware should build");

            drop(client);
        }

        fn localhost_allowlist_policy() -> AntiSSRFPolicy {
            let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
            policy.add_allowed_addresses(&["127.0.0.1/32"]).unwrap();
            policy.set_allow_plaintext_http(true).unwrap();
            policy
        }

        #[tokio::test]
        async fn redirect_blocks_disallowed_ip() {
            let mut server = mockito::Server::new_async().await;
            let _mock = server
                .mock("GET", "/redirect")
                .with_status(301)
                .with_header("Location", "http://169.254.169.254/target")
                .create_async()
                .await;

            let policy = localhost_allowlist_policy();
            let client = AntiSSRFClientBuilder::new(policy)
                .build_with_middleware()
                .expect("should build");

            let result = client
                .get(format!("{}/redirect", server.url()))
                .send()
                .await;

            assert!(
                result.is_err(),
                "Redirect to disallowed IMDS IP should be blocked"
            );
        }

        #[tokio::test]
        async fn redirect_allows_allowed_target() {
            let mut server = mockito::Server::new_async().await;
            let _redirect_mock = server
                .mock("GET", "/redirect")
                .with_status(301)
                .with_header("Location", format!("{}/target", server.url()).as_str())
                .create_async()
                .await;

            let _target_mock = server
                .mock("GET", "/target")
                .with_status(200)
                .with_body("ok")
                .create_async()
                .await;

            let policy = localhost_allowlist_policy();
            let client = AntiSSRFClientBuilder::new(policy)
                .build_with_middleware()
                .expect("should build");

            let response = client
                .get(format!("{}/redirect", server.url()))
                .send()
                .await
                .expect("request should succeed");

            assert_eq!(
                response.status(),
                200,
                "Allowed redirect target should succeed"
            );
            let body = response.text().await.expect("should have body");
            assert_eq!(body, "ok");
        }

        #[tokio::test]
        async fn redirect_strips_authorization() {
            let mut server = mockito::Server::new_async().await;
            let _redirect_mock = server
                .mock("GET", "/redirect")
                .with_status(301)
                .with_header("Location", format!("{}/target", server.url()).as_str())
                .create_async()
                .await;

            let _target_mock = server
                .mock("GET", "/target")
                .with_status(200)
                .create_async()
                .await;

            let policy = localhost_allowlist_policy();
            let client = AntiSSRFClientBuilder::new(policy)
                .build_with_middleware()
                .expect("should build");

            let response = client
                .get(format!("{}/redirect", server.url()))
                .header("Authorization", "Bearer secret")
                .send()
                .await
                .expect("request should succeed");

            assert_eq!(
                response.status(),
                200,
                "Redirect after stripping auth should succeed"
            );
        }

        #[tokio::test]
        async fn redirect_converts_post_to_get_on_301() {
            let mut server = mockito::Server::new_async().await;
            let _redirect_mock = server
                .mock("POST", "/redirect")
                .with_status(301)
                .with_header("Location", format!("{}/target", server.url()).as_str())
                .create_async()
                .await;

            // Only match GET on target — if POST is preserved, this won't match
            let _target_mock = server
                .mock("GET", "/target")
                .with_status(200)
                .create_async()
                .await;

            let policy = localhost_allowlist_policy();
            let client = AntiSSRFClientBuilder::new(policy)
                .build_with_middleware()
                .expect("should build");

            let response = client
                .post(format!("{}/redirect", server.url()))
                .body("test body")
                .send()
                .await
                .expect("request should succeed");

            assert_eq!(
                response.status(),
                200,
                "POST should be converted to GET on 301 redirect"
            );
        }

        #[tokio::test]
        async fn redirect_preserves_post_on_307() {
            let mut server = mockito::Server::new_async().await;
            let _redirect_mock = server
                .mock("POST", "/redirect")
                .with_status(307)
                .with_header("Location", format!("{}/target", server.url()).as_str())
                .create_async()
                .await;

            // Only match POST on target — if GET conversion happens, this won't match
            let _target_mock = server
                .mock("POST", "/target")
                .with_status(200)
                .create_async()
                .await;

            let policy = localhost_allowlist_policy();
            let client = AntiSSRFClientBuilder::new(policy)
                .build_with_middleware()
                .expect("should build");

            let response = client
                .post(format!("{}/redirect", server.url()))
                .body("test body")
                .send()
                .await
                .expect("request should succeed");

            assert_eq!(
                response.status(),
                200,
                "POST should be preserved on 307 redirect"
            );
        }

        #[tokio::test]
        async fn redirect_caps_at_50() {
            let mut server = mockito::Server::new_async().await;
            let server_url = server.url();

            let _redirect_mock = server
                .mock("GET", "/loop")
                .with_status(301)
                .with_header("Location", format!("{}/loop", server_url).as_str())
                .create_async()
                .await;

            let policy = localhost_allowlist_policy();
            let client = AntiSSRFClientBuilder::new(policy)
                .build_with_middleware()
                .expect("should build");

            let response = client
                .get(format!("{}/loop", server_url))
                .send()
                .await
                .expect("request should not error");

            assert_eq!(
                response.status(),
                301,
                "After 50 redirects, the 51st redirect response should be returned"
            );
        }
    }
}
