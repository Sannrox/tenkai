//! Sealed values the Helm executor writes as immutable Kubernetes Secrets
//! (ADR 0045 §4, ADR 0048 §4).
//!
//! The environment runtime opens each value in memory and hands it over in
//! [`SoftwareApplyRequest::opened_secrets`]. Every secret name the step
//! writes becomes one Secret `<instance>-<secret>-<digest8>` in the
//! namespace `helm` installs into, holding that secret's keys. The name is
//! content-addressed, so a retry finds the Secret it already wrote, and the
//! chart receives it as `tenkai.secrets.<secret>.name`. Tenkai never writes
//! over a Secret it does not own.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use tenkai::software_executor::SoftwareApplyRequest;

use crate::in_process_kubernetes::{
    block_on, bounded, ensure_namespace, is_already_exists, live_client,
};

const OWNER_LABEL: &str = "tenkai.dev/owner";
const OWNER: &str = "tenkai";
const INSTANCE_LABEL: &str = "tenkai.dev/instance";
const SECRET_LABEL: &str = "tenkai.dev/secret";

/// The Secrets API the writer needs, so tests can stand in for a cluster.
pub(crate) trait SecretApi {
    fn get(&self, namespace: &str, name: &str) -> Result<Option<Secret>>;
    /// Create `secret`. `Ok(false)` when one of that name already exists.
    fn create(&self, namespace: &str, secret: &Secret) -> Result<bool>;
    fn list(&self, namespace: &str, selector: &str) -> Result<Vec<Secret>>;
    fn delete(&self, namespace: &str, name: &str) -> Result<()>;
}

/// The Secret one secret name of `request` is written to.
struct Planned {
    secret: String,
    name: String,
}

/// Refuse a name Kubernetes cannot carry in an object name and label, or
/// Helm in a `--set` path: lowercase letters, digits and '-', at most 63.
fn require_dns_label(what: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-');
    if !valid {
        bail!(
            "{what} {value:?} cannot name a Kubernetes Secret; sealed secrets on helm need lowercase letters, digits and '-' (at most 63)"
        );
    }
    Ok(())
}

/// One entry per secret name, in name order, with its content-addressed
/// Secret name. `<digest8>` is the first 8 hex characters of a digest over
/// the secret's keys and their sealed digests, so a secret with several keys
/// still gets one name per content.
fn planned(request: &SoftwareApplyRequest) -> Result<Vec<Planned>> {
    require_dns_label("instance", request.instance_name())?;
    let mut digests: BTreeMap<&str, Sha256> = BTreeMap::new();
    for opened in &request.opened_secrets {
        let hasher = digests.entry(&opened.secret).or_default();
        hasher.update(opened.key.as_bytes());
        hasher.update([0]);
        hasher.update(opened.digest.as_bytes());
        hasher.update([b'\n']);
    }
    digests
        .into_iter()
        .map(|(secret, hasher)| {
            require_dns_label("secret", secret)?;
            let digest = format!("{:x}", hasher.finalize());
            Ok(Planned {
                secret: secret.to_owned(),
                name: format!("{}-{secret}-{}", request.instance_name(), &digest[..8]),
            })
        })
        .collect()
}

fn owned_by(secret: &Secret, instance: &str, name: &str) -> bool {
    let labels = secret.metadata.labels.as_ref();
    let label = |key: &str| {
        labels
            .and_then(|labels| labels.get(key))
            .map(String::as_str)
    };
    label(OWNER_LABEL) == Some(OWNER)
        && label(INSTANCE_LABEL) == Some(instance)
        && label(SECRET_LABEL) == Some(name)
}

/// Write every opened value of `request` and return the `--set` values that
/// name the Secrets for the chart. A Secret already there is reused when
/// Tenkai wrote it for this instance and secret, and refused otherwise.
pub(crate) fn write(api: &dyn SecretApi, request: &SoftwareApplyRequest) -> Result<Vec<String>> {
    let namespace = &request.environment;
    let instance = request.instance_name();
    let mut sets = Vec::new();
    for planned in planned(request)? {
        let existing = match api.get(namespace, &planned.name)? {
            Some(existing) => Some(existing),
            None => {
                let mut secret = Secret {
                    metadata: ObjectMeta {
                        name: Some(planned.name.clone()),
                        labels: Some(BTreeMap::from([
                            (OWNER_LABEL.to_owned(), OWNER.to_owned()),
                            (INSTANCE_LABEL.to_owned(), instance.to_owned()),
                            (SECRET_LABEL.to_owned(), planned.secret.clone()),
                        ])),
                        ..ObjectMeta::default()
                    },
                    immutable: Some(true),
                    type_: Some("Opaque".into()),
                    data: Some(
                        request
                            .opened_secrets
                            .iter()
                            .filter(|opened| opened.secret == planned.secret)
                            .map(|opened| (opened.key.clone(), ByteString(opened.value.to_vec())))
                            .collect(),
                    ),
                    ..Secret::default()
                };
                let created = api.create(namespace, &secret);
                for value in secret.data.iter_mut().flat_map(|data| data.values_mut()) {
                    value.0.zeroize();
                }
                // Another attempt may have created it first.
                if created? {
                    None
                } else {
                    api.get(namespace, &planned.name)?
                }
            }
        };
        if let Some(existing) = existing
            && !owned_by(&existing, instance, &planned.secret)
        {
            bail!(
                "Secret {} in {namespace} exists and is not Tenkai's; Tenkai never writes over it",
                planned.name
            );
        }
        sets.push(format!(
            "tenkai.secrets.{}.name={}",
            planned.secret, planned.name
        ));
    }
    Ok(sets)
}

fn instance_selector(instance: &str) -> String {
    format!("{OWNER_LABEL}={OWNER},{INSTANCE_LABEL}={instance}")
}

/// Delete Tenkai's Secrets of this instance that nothing reads any more.
/// For each secret name it keeps the Secret `request` wrote, if any, and
/// the newest other one, which a rollback or a pod of the previous template
/// still reads. A secret name the instance stopped using keeps only that one.
pub(crate) fn prune(api: &dyn SecretApi, request: &SoftwareApplyRequest) -> Result<()> {
    let namespace = &request.environment;
    let current: Vec<String> = planned(request)?.into_iter().map(|p| p.name).collect();
    let mut by_secret: BTreeMap<String, Vec<Secret>> = BTreeMap::new();
    for secret in api.list(namespace, &instance_selector(request.instance_name()))? {
        let name = secret.metadata.name.as_deref().unwrap_or_default();
        if current.iter().any(|current| current == name) {
            continue;
        }
        let label = secret
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(SECRET_LABEL))
            .cloned()
            .unwrap_or_default();
        by_secret.entry(label).or_default().push(secret);
    }
    for mut others in by_secret.into_values() {
        others.sort_by(|a, b| {
            b.metadata
                .creation_timestamp
                .cmp(&a.metadata.creation_timestamp)
        });
        for stale in others.iter().skip(1) {
            if let Some(name) = &stale.metadata.name {
                api.delete(namespace, name)?;
            }
        }
    }
    Ok(())
}

/// Delete every Secret Tenkai wrote for the instance `request` removes.
pub(crate) fn remove_all(api: &dyn SecretApi, request: &SoftwareApplyRequest) -> Result<()> {
    let namespace = &request.environment;
    for secret in api.list(namespace, &instance_selector(request.instance_name()))? {
        if let Some(name) = &secret.metadata.name {
            api.delete(namespace, name)?;
        }
    }
    Ok(())
}

/// [`SecretApi`] against the cluster the request's configuration names.
pub(crate) struct LiveSecrets(kube::Client);

impl LiveSecrets {
    /// Connect through `cluster_config` and make sure `namespace` exists, as
    /// `helm --create-namespace` would, so the Secret can land before the
    /// release.
    pub(crate) fn connect(cluster_config: &Path, namespace: &str) -> Result<Self> {
        block_on(async {
            let client = bounded(live_client(cluster_config)).await?;
            bounded(ensure_namespace(&client, namespace)).await?;
            Ok(Self(client))
        })
    }

    /// Connect through `cluster_config` only, for cleanup: a removal must
    /// not need the cluster-scoped Namespace access that [`Self::connect`]
    /// uses, only list and delete of Secrets in the release's namespace.
    pub(crate) fn connect_existing(cluster_config: &Path) -> Result<Self> {
        block_on(async { Ok(Self(bounded(live_client(cluster_config)).await?)) })
    }

    fn api(&self, namespace: &str) -> kube::Api<Secret> {
        kube::Api::namespaced(self.0.clone(), namespace)
    }
}

impl SecretApi for LiveSecrets {
    fn get(&self, namespace: &str, name: &str) -> Result<Option<Secret>> {
        block_on(bounded(async {
            self.api(namespace)
                .get_opt(name)
                .await
                .with_context(|| format!("reading Secret {name} in {namespace}"))
        }))
    }

    fn create(&self, namespace: &str, secret: &Secret) -> Result<bool> {
        let name = secret.metadata.name.as_deref().unwrap_or_default();
        block_on(bounded(async {
            match self
                .api(namespace)
                .create(&kube::api::PostParams::default(), secret)
                .await
            {
                Ok(_) => Ok(true),
                Err(error) if is_already_exists(&error) => Ok(false),
                // The API's error names the object, never its data.
                Err(error) => Err(anyhow::anyhow!(
                    "creating Secret {name} in {namespace}: {error}"
                )),
            }
        }))
    }

    fn list(&self, namespace: &str, selector: &str) -> Result<Vec<Secret>> {
        block_on(bounded(async {
            Ok(self
                .api(namespace)
                .list_metadata(&kube::api::ListParams::default().labels(selector))
                .await
                .with_context(|| format!("listing Tenkai Secrets in {namespace}"))?
                .items
                .into_iter()
                .map(|item| Secret {
                    metadata: item.metadata,
                    ..Secret::default()
                })
                .collect())
        }))
    }

    fn delete(&self, namespace: &str, name: &str) -> Result<()> {
        block_on(bounded(async {
            match self
                .api(namespace)
                .delete(name, &kube::api::DeleteParams::default())
                .await
            {
                Ok(_) => Ok(()),
                Err(kube::Error::Api(status)) if status.code == 404 => Ok(()),
                Err(error) => Err(anyhow::anyhow!(
                    "deleting Secret {name} in {namespace}: {error}"
                )),
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tenkai::software_executor::OpenedSecret;

    /// Secrets of one namespace, with creation order as the timestamp.
    #[derive(Default)]
    struct Memory(RefCell<Vec<Secret>>);

    impl SecretApi for Memory {
        fn get(&self, _: &str, name: &str) -> Result<Option<Secret>> {
            Ok(self
                .0
                .borrow()
                .iter()
                .find(|secret| secret.metadata.name.as_deref() == Some(name))
                .cloned())
        }

        fn create(&self, namespace: &str, secret: &Secret) -> Result<bool> {
            if self
                .get(namespace, secret.metadata.name.as_deref().unwrap())?
                .is_some()
            {
                return Ok(false);
            }
            let mut secret = secret.clone();
            let order = self.0.borrow().len() as i64;
            secret.metadata.creation_timestamp =
                Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::chrono::DateTime::from_timestamp(order, 0).unwrap(),
                ));
            self.0.borrow_mut().push(secret);
            Ok(true)
        }

        fn list(&self, _: &str, selector: &str) -> Result<Vec<Secret>> {
            let wanted: Vec<(&str, &str)> = selector
                .split(',')
                .map(|term| term.split_once('=').unwrap())
                .collect();
            Ok(self
                .0
                .borrow()
                .iter()
                .filter(|secret| {
                    let labels = secret.metadata.labels.clone().unwrap_or_default();
                    wanted
                        .iter()
                        .all(|(key, value)| labels.get(*key).map(String::as_str) == Some(*value))
                })
                .cloned()
                .collect())
        }

        fn delete(&self, _: &str, name: &str) -> Result<()> {
            self.0
                .borrow_mut()
                .retain(|secret| secret.metadata.name.as_deref() != Some(name));
            Ok(())
        }
    }

    impl Memory {
        fn names(&self) -> Vec<String> {
            self.0
                .borrow()
                .iter()
                .filter_map(|secret| secret.metadata.name.clone())
                .collect()
        }
    }

    fn request(values: &[(&str, &str, &str, &[u8])]) -> SoftwareApplyRequest {
        let mut request = tenkai::software_executor::request_from_parts(
            "api",
            "1.0.0",
            "prod",
            Path::new("/nonexistent"),
            "tenkai:release:api@1.0.0",
        );
        request.opened_secrets = values
            .iter()
            .map(|(secret, key, digest, value)| OpenedSecret {
                secret: (*secret).into(),
                key: (*key).into(),
                digest: (*digest).into(),
                value: zeroize::Zeroizing::new(value.to_vec()),
            })
            .collect();
        request
    }

    #[test]
    fn a_sealed_value_lands_once_in_an_immutable_secret_the_chart_is_told_about() {
        let api = Memory::default();
        let request = request(&[
            ("db", "password", "sha256:aa", b"hunter2"),
            ("db", "user", "sha256:bb", b"api"),
        ]);
        let sets = write(&api, &request).unwrap();
        let [set] = sets.as_slice() else {
            panic!("one Secret per secret name: {sets:?}");
        };
        let name = set.strip_prefix("tenkai.secrets.db.name=").unwrap();
        assert!(name.starts_with("api-db-") && name.len() == "api-db-".len() + 8);
        let secret = api.get("prod", name).unwrap().unwrap();
        assert_eq!(secret.immutable, Some(true));
        let data = secret.data.unwrap();
        assert_eq!(data["password"].0, b"hunter2");
        assert_eq!(data["user"].0, b"api");

        // A retry after a crash finds the Secret it wrote.
        assert_eq!(write(&api, &request).unwrap(), sets);
        assert_eq!(api.names().len(), 1);
    }

    #[test]
    fn a_secret_tenkai_does_not_own_is_never_written_over() {
        let api = Memory::default();
        let request = request(&[("db", "password", "sha256:aa", b"hunter2")]);
        let name = write(&Memory::default(), &request).unwrap()[0]
            .split_once('=')
            .unwrap()
            .1
            .to_owned();
        api.create(
            "prod",
            &Secret {
                metadata: ObjectMeta {
                    name: Some(name.clone()),
                    ..ObjectMeta::default()
                },
                ..Secret::default()
            },
        )
        .unwrap();
        let refused = write(&api, &request).unwrap_err().to_string();
        assert!(refused.contains("not Tenkai's"), "{refused}");
        assert!(!refused.contains("hunter2"), "{refused}");
        assert!(api.get("prod", &name).unwrap().unwrap().data.is_none());
    }

    #[test]
    fn pruning_keeps_the_current_and_the_previous_secret_only() {
        let api = Memory::default();
        let mut names = Vec::new();
        for digest in ["sha256:01", "sha256:02", "sha256:03"] {
            let request = request(&[("db", "password", digest, b"v")]);
            names.push(
                write(&api, &request).unwrap()[0]
                    .split_once('=')
                    .unwrap()
                    .1
                    .to_owned(),
            );
            prune(&api, &request).unwrap();
        }
        // Another instance's Secret of the same name is left alone.
        let mut worker = request(&[("db", "password", "sha256:01", b"v")]);
        worker.instance = "worker".into();
        write(&api, &worker).unwrap();
        prune(&api, &request(&[("db", "password", "sha256:03", b"v")])).unwrap();
        let left = api.names();
        assert!(!left.contains(&names[0]), "{left:?}");
        assert!(
            left.contains(&names[1]) && left.contains(&names[2]),
            "{left:?}"
        );
        assert_eq!(left.len(), 3, "{left:?}");

        // A secret the instance stopped using keeps only its newest Secret.
        let cache = request(&[("cache", "token", "sha256:04", b"v")]);
        write(&api, &cache).unwrap();
        prune(&api, &cache).unwrap();
        let left = api.names();
        assert!(
            !left.contains(&names[1]) && left.contains(&names[2]),
            "{left:?}"
        );

        // Removing the instance deletes all of its Secrets, found by their
        // labels: the removal carries no opened values.
        remove_all(&api, &request(&[])).unwrap();
        let left = api.names();
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(left[0].starts_with("worker-"), "{left:?}");
    }

    #[test]
    fn names_kubernetes_or_helm_cannot_carry_are_refused() {
        let long = "d".repeat(64);
        for secret in ["DB", "db_main", "db.main", "db+x", long.as_str()] {
            let request = request(&[(secret, "password", "sha256:aa", b"hunter2")]);
            let refused = write(&Memory::default(), &request).unwrap_err().to_string();
            assert!(
                refused.contains("cannot name a Kubernetes Secret"),
                "{refused}"
            );
            assert!(!refused.contains("hunter2"), "{refused}");
        }
    }
}
