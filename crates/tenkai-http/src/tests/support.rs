use super::*;

pub(super) struct FixedReconciler;

impl ReconcilePort for FixedReconciler {
    fn reconcile(&self) -> ReconcileFuture<'_> {
        Box::pin(async {
            Ok(TickReport {
                environments: vec![tenkai::reconciler::EnvironmentResult {
                    environment: "prod".into(),
                    status: tenkai::reconciler::EnvironmentStatus::Current,
                }],
            })
        })
    }

    fn reconcile_environments(&self, environments: Vec<String>) -> ReconcileFuture<'_> {
        Box::pin(async move {
            Ok(TickReport {
                environments: environments
                    .into_iter()
                    .map(|environment| tenkai::reconciler::EnvironmentResult {
                        environment,
                        status: tenkai::reconciler::EnvironmentStatus::Current,
                    })
                    .collect(),
            })
        })
    }

    fn pending_work(&self, environment: String) -> WorkFuture<'_> {
        Box::pin(async move {
            Ok(Some(tenkai::plan::Plan {
                format_version: 1,
                id: "plan-1".into(),
                content_id: "sha256:plan".into(),
                environment,
                created_at: 1,
                inputs: Vec::new(),
                steps: Vec::new(),
                state: tenkai::plan::PlanState::Computed,
                gates_skipped: None,
                status_detail: String::new(),
                maintenance_blocked: false,
                prior_warnings: Vec::new(),
                recalled_recovery_reason: None,
            }))
        })
    }

    fn check_health(&self) -> HealthFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn complete_work(
        &self,
        _environment: String,
        _completion: tenkai::runtime_delivery::RuntimeCompletion,
    ) -> CompletionFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn validate_completion(
        &self,
        _environment: String,
        _completion: tenkai::runtime_delivery::RuntimeCompletion,
    ) -> CompletionFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn list_environments(&self) -> ListEnvFuture<'_> {
        Box::pin(async {
            Ok(vec![tenkai::plan::EnvironmentListEntry {
                name: "prod".into(),
                id: "tenkai:env:prod".into(),
                description: "fixture".into(),
                subscription_count: 0,
                deployed_product_count: 0,
                lease_held: false,
            }])
        })
    }

    fn inspect_environment(&self, environment: String) -> InspectEnvFuture<'_> {
        Box::pin(async move {
            Ok(tenkai::plan::EnvironmentInspectReport {
                name: environment,
                id: "tenkai:env:prod".into(),
                description: "fixture".into(),
                subscriptions: Vec::new(),
                facts: Default::default(),
                overlays: Default::default(),
                lease: tenkai::apply::EnvironmentLeaseInspect {
                    held: false,
                    owner: None,
                    generation: None,
                    expires_at_ms: None,
                    status: "absent".into(),
                },
                latest_plan: None,
                maintenance: None,
                constraints: Vec::new(),
                terminal_outcomes: Vec::new(),
                execution_note: "fixture".into(),
                observed_type_digest: None,
                observed_runtime_digest: None,
                module_activations: Vec::new(),
                retirement: None,
                preview: None,
            })
        })
    }

    fn environment_status(&self, _environment: String) -> StatusEnvFuture<'_> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn fleet_status(&self) -> FleetStatusFuture<'_> {
        Box::pin(async {
            Ok(tenkai::plan::FleetStatusReport {
                environments: vec![tenkai::plan::FleetEnvironmentRow {
                    name: "prod".into(),
                    id: "tenkai:env:prod".into(),
                    description: "fixture".into(),
                    subscription_count: 0,
                    products_current: 0,
                    products_behind: 0,
                    products_missing: 0,
                    unhealthy: false,
                    health_summary: "n/a".into(),
                    lease_held: false,
                    latest_plan_state: None,
                    posture: "empty".into(),
                }],
                environment_count: 1,
                environments_current: 0,
                environments_behind: 0,
                environments_unhealthy: 0,
                environments_empty: 1,
            })
        })
    }

    fn fleet_status_without_outcome_export(&self) -> FleetStatusFuture<'_> {
        self.fleet_status()
    }

    fn apply_inventory_facts(
        &self,
        _environment: String,
        facts: std::collections::BTreeMap<String, String>,
    ) -> InventoryFuture<'_> {
        Box::pin(async move {
            // Fixture: accept admitted keys only (mirror plan validation lightly).
            for key in facts.keys() {
                if !tenkai::plan::ENVIRONMENT_FACT_KEYS.contains(&key.as_str()) {
                    anyhow::bail!("unknown environment fact {key:?}");
                }
            }
            let mut applied: Vec<String> = facts.into_keys().collect();
            applied.sort();
            Ok(applied)
        })
    }

    fn diagnostics_snapshot(&self) -> tenkai::reconciler::ReconcileDiagnostics {
        tenkai::reconciler::ReconcileDiagnostics {
            ticks_total: 1,
            ticks_failed: 0,
            last_outcome: "ok".into(),
            last_environments_total: 1,
            last_environments_failed: 0,
            environments_busy_total: 0,
        }
    }
}

pub(super) fn app() -> (Router, Arc<tenkai::storage::SqliteStore>) {
    let store = Arc::new(tenkai::storage::SqliteStore::open_in_memory().unwrap());
    store
        .put_environment(&tenkai::storage::EnvironmentRecord {
            id: "prod".into(),
            revision: 0,
            configuration_json: "{}".into(),
        })
        .unwrap();
    let app = router(
        ServerConfig::community(
            "management-secret",
            HashMap::from([("runtime-secret".into(), "prod".into())]),
        ),
        Arc::new(FixedReconciler),
        store.clone(),
    )
    .unwrap();
    (app, store)
}
