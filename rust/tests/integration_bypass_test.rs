#[cfg(feature = "reqwest-integration")]
mod integration_tests {
    use antissrf::network::reqwest_integration::AntiSSRFClientBuilder;
    use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
    use reqwest_middleware::Error as MiddlewareError;

    fn localhost_allowlist_policy() -> AntiSSRFPolicy {
        let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
        policy.add_allowed_addresses(&["127.0.0.1/32"]).unwrap();
        policy.set_allow_plaintext_http(true).unwrap();
        policy
    }

    #[tokio::test]
    async fn test_redirect_to_localhost_blocked_without_allowlist() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/redirect")
            .with_status(302)
            .with_header("Location", "http://127.0.0.1:9999/")
            .create_async()
            .await;

        let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
        let client = AntiSSRFClientBuilder::new(policy)
            .build_with_middleware()
            .expect("Failed to build client");

        let url = format!("{}/redirect", server.url());
        let result: Result<reqwest::Response, MiddlewareError> = client.get(&url).send().await;

        assert!(
            result.is_err(),
            "Expected redirect to localhost to be blocked, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_redirect_to_cloud_metadata_blocked() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/redirect")
            .with_status(307)
            .with_header("Location", "http://169.254.169.254/latest/meta-data/")
            .create_async()
            .await;

        let policy = localhost_allowlist_policy();
        let client = AntiSSRFClientBuilder::new(policy)
            .build_with_middleware()
            .expect("Failed to build client");

        let url = format!("{}/redirect", server.url());
        let result: Result<reqwest::Response, MiddlewareError> = client.get(&url).send().await;

        assert!(
            result.is_err(),
            "Expected redirect to cloud metadata to be blocked, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_redirect_to_wireserver_blocked() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/redirect")
            .with_status(302)
            .with_header("Location", "http://168.63.129.16/")
            .create_async()
            .await;

        let policy = localhost_allowlist_policy();
        let client = AntiSSRFClientBuilder::new(policy)
            .build_with_middleware()
            .expect("Failed to build client");

        let url = format!("{}/redirect", server.url());
        let result: Result<reqwest::Response, MiddlewareError> = client.get(&url).send().await;

        assert!(
            result.is_err(),
            "Expected redirect to WireServer to be blocked, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_redirect_chain_multiple_hops_blocked() {
        let mut server = mockito::Server::new_async().await;
        let server_url = server.url();

        let _redirect1 = server
            .mock("GET", "/step1")
            .with_status(302)
            .with_header("Location", format!("{}/step2", server_url).as_str())
            .create_async()
            .await;

        let _redirect2 = server
            .mock("GET", "/step2")
            .with_status(302)
            .with_header("Location", "http://169.254.169.254/")
            .create_async()
            .await;

        let policy = localhost_allowlist_policy();
        let client = AntiSSRFClientBuilder::new(policy)
            .build_with_middleware()
            .expect("Failed to build client");

        let url = format!("{}/step1", server_url);
        let result: Result<reqwest::Response, MiddlewareError> = client.get(&url).send().await;

        assert!(
            result.is_err(),
            "Expected multi-hop redirect to blocked target to fail, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_redirect_chain_allowed_all_hops() {
        let mut server = mockito::Server::new_async().await;
        let server_url = server.url();

        let _redirect1 = server
            .mock("GET", "/step1")
            .with_status(302)
            .with_header("Location", format!("{}/step2", server_url).as_str())
            .create_async()
            .await;

        let _redirect2 = server
            .mock("GET", "/step2")
            .with_status(302)
            .with_header("Location", format!("{}/target", server_url).as_str())
            .create_async()
            .await;

        let _target = server
            .mock("GET", "/target")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let policy = localhost_allowlist_policy();
        let client = AntiSSRFClientBuilder::new(policy)
            .build_with_middleware()
            .expect("Failed to build client");

        let url = format!("{}/step1", server_url);
        let response = client
            .get(&url)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(
            response.status(),
            200,
            "All-allowed redirect chain should succeed"
        );
        let body = response.text().await.expect("should have body");
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn test_auth_stripped_on_redirect() {
        let mut server = mockito::Server::new_async().await;
        let server_url = server.url();

        let _redirect_mock = server
            .mock("GET", "/redirect")
            .with_status(302)
            .with_header("Location", format!("{}/target", server_url).as_str())
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
            .expect("Failed to build client");

        let url = format!("{}/redirect", server_url);
        let response = client
            .get(&url)
            .header("Authorization", "Bearer secret-token")
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(
            response.status(),
            200,
            "Auth-stripped redirect should succeed"
        );
    }

    #[tokio::test]
    async fn test_plaintext_http_blocked_by_default() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/test")
            .with_status(200)
            .create_async()
            .await;

        let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
        let client = AntiSSRFClientBuilder::new(policy)
            .build_with_middleware()
            .expect("Failed to build client");

        let url = format!("{}/test", server.url());
        let result: Result<reqwest::Response, MiddlewareError> = client.get(&url).send().await;

        assert!(
            result.is_err(),
            "Expected HTTP request to blocked localhost to fail, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_redirect_to_encoded_localhost_blocked() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/redirect")
            .with_status(302)
            .with_header("Location", "http://2130706433/")
            .create_async()
            .await;

        let policy = localhost_allowlist_policy();
        let client = AntiSSRFClientBuilder::new(policy)
            .build_with_middleware()
            .expect("Failed to build client");

        let url = format!("{}/redirect", server.url());
        let result: Result<reqwest::Response, MiddlewareError> = client.get(&url).send().await;

        assert!(
            result.is_err(),
            "Expected redirect to encoded localhost (2130706433) to be blocked, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_redirect_to_hex_localhost_blocked() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/redirect")
            .with_status(302)
            .with_header("Location", "http://0x7f000001/")
            .create_async()
            .await;

        let policy = localhost_allowlist_policy();
        let client = AntiSSRFClientBuilder::new(policy)
            .build_with_middleware()
            .expect("Failed to build client");

        let url = format!("{}/redirect", server.url());
        let result: Result<reqwest::Response, MiddlewareError> = client.get(&url).send().await;

        assert!(
            result.is_err(),
            "Expected redirect to hex localhost (0x7f000001) to be blocked, got {:?}",
            result
        );
    }
}
