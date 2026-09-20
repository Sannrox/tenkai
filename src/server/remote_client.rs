use crate::reconciler::TickReport;

#[derive(Clone)]
pub struct RemoteClient {
    pub(super) base_url: String,
    pub(super) token: String,
    pub(super) http: reqwest::Client,
}

impl RemoteClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> anyhow::Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        anyhow::ensure!(!base_url.is_empty(), "server URL must not be empty");
        let parsed = url::Url::parse(&base_url)?;
        let secure = parsed.scheme() == "https";
        let loopback_http = parsed.scheme() == "http"
            && parsed.host().is_some_and(|host| match host {
                url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
                url::Host::Ipv4(address) => address.is_loopback(),
                url::Host::Ipv6(address) => address.is_loopback(),
            });
        anyhow::ensure!(
            secure || loopback_http,
            "remote management tokens require HTTPS or an HTTP loopback URL"
        );
        let token = token.into();
        anyhow::ensure!(!token.is_empty(), "management token must not be empty");
        Ok(Self {
            base_url,
            token,
            http: reqwest::Client::new(),
        })
    }

    pub async fn reconcile(&self) -> anyhow::Result<TickReport> {
        self.request_json(reqwest::Method::POST, "/v1/reconcile")
            .await
    }

    pub async fn list_environments(
        &self,
    ) -> anyhow::Result<Vec<crate::plan::EnvironmentListEntry>> {
        self.request_json(reqwest::Method::GET, "/v1/environments")
            .await
    }

    pub async fn inspect_environment(
        &self,
        environment: &str,
    ) -> anyhow::Result<crate::plan::EnvironmentInspectReport> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/environments/{environment}"),
        )
        .await
    }

    pub async fn environment_status(
        &self,
        environment: &str,
    ) -> anyhow::Result<Vec<crate::plan::StatusRow>> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/v1/environments/{environment}/status"),
        )
        .await
    }

    pub async fn fleet_status(&self) -> anyhow::Result<crate::plan::FleetStatusReport> {
        self.request_json(reqwest::Method::GET, "/v1/fleet/status")
            .await
    }

    pub(super) async fn request_json<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> anyhow::Result<T> {
        self.request_json_body::<(), T>(method, path, None).await
    }

    pub(super) async fn request_json_body<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> anyhow::Result<T> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(&self.token);
        if let Some(operation_id) = crate::telemetry::current_operation_id() {
            request = request.header("x-request-id", operation_id);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            anyhow::bail!("remote server returned {status}: {detail}");
        }
        Ok(response.json().await?)
    }
}
