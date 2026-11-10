//! Prepare and plan the environment's identity issuer (ADR 0046 §2).

use super::*;
use crate::management_lifecycle::PlanRequest;

impl ManagementOperations {
    /// Ask `environment`'s runtimes for a candidate key for the next issuer
    /// generation. Needs no approval: a candidate is used only once an
    /// approved plan names its fingerprint.
    pub async fn prepare_identity_issuer(
        &self,
        credential: &CredentialMaterial,
        environment: &str,
        request: PlanRequest,
    ) -> Result<ManagementLifecycleResult, ManagementError> {
        let context = self
            .admit_identity_issuer(credential, environment, &request)
            .await?;
        let actor = &context.audit_principal();
        self.audit(actor, "identity_issuer.prepare.requested")?;
        let mut ctx = self.catalog_ctx(&context)?;
        let generation = crate::identity_issuer::request_candidate(&mut ctx, environment)
            .await
            .map_err(map_plan_lifecycle_error)?;
        self.audit(actor, "identity_issuer.prepare.completed")?;
        Ok(ManagementLifecycleResult::new(
            ManagementLifecycleOperation::Plan,
            format!(
                "{environment} asks its runtimes for an issuer candidate of generation {generation}; plan it once env inspect shows the candidate"
            ),
            None,
        ))
    }

    /// A plan whose one step activates `environment`'s uploaded issuer
    /// candidate. It names the candidate's fingerprint, so approving it
    /// approves exactly that key.
    pub async fn plan_identity_issuer(
        &self,
        credential: &CredentialMaterial,
        environment: &str,
        request: PlanRequest,
    ) -> Result<ManagementLifecycleResult, ManagementError> {
        let context = self
            .admit_identity_issuer(credential, environment, &request)
            .await?;
        let actor = &context.audit_principal();
        self.audit(actor, "plan.identity_issuer.requested")?;
        let mut ctx = self.catalog_ctx(&context)?;
        let env_obj = crate::environment::environment(&mut ctx, environment)
            .await
            .map_err(map_plan_lifecycle_error)?;
        let step = crate::identity_issuer::activation_step(&env_obj, environment)
            .map_err(|error| ManagementError::BadRequest(format!("{error:#}")))?;
        let issuer = step.issuer.as_ref().expect("activation steps carry a key");
        let message_key = format!(
            "generation {} with key {}",
            issuer.key.generation, issuer.key.fingerprint
        );
        let stored = crate::plan::create_from_steps(&mut ctx, environment, vec![step])
            .await
            .map_err(map_plan_lifecycle_error)?;
        self.audit(actor, "plan.identity_issuer.completed")?;
        let digest = format!(
            "sha256:{}",
            stored
                .executable_digest()
                .map_err(map_plan_lifecycle_error)?
        );
        Ok(ManagementLifecycleResult::new(
            ManagementLifecycleOperation::Plan,
            format!(
                "identity issuer plan {} for {message_key} requires signed approval",
                stored.id
            ),
            Some(stored.id),
        )
        .with_digest(digest))
    }

    /// A plan that wraps `environment`'s current issuer key for one more
    /// recipient: an unrevoked runtime key or the recovery key. It is its own
    /// plan, apart from `secret rewrap`: the runtime that holds the issuer
    /// key need not hold the sealed values, and one plan needing both could
    /// have no runtime able to run it.
    pub async fn rewrap_identity_issuer(
        &self,
        credential: &CredentialMaterial,
        environment: &str,
        request: management_lifecycle::SealedRewrapRequest,
    ) -> Result<ManagementLifecycleResult, ManagementError> {
        let context = self.authenticate(credential)?;
        self.admit_agent_plan(&context, "plan.identity_issuer")?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        management_lifecycle::admit_sealed_rewrap(
            &request,
            environment,
            context.principal.kind,
            self.granted_environment(credential, &context),
        )
        .map_err(map_lifecycle_error)?;
        if !request.recovered.is_empty() {
            return Err(ManagementError::BadRequest(
                "the identity issuer is rotated, not recovered; recovered wraps are for sealed values"
                    .into(),
            ));
        }
        self.require_environment_visible(&context, environment)
            .await?;
        self.require_current_generation(&context, environment, request.expected_generation)
            .await?;
        let recipient = crate::sealing_key::normalize_fingerprint(&request.recipient)
            .map_err(|error| ManagementError::BadRequest(error.to_string()))?;
        let recipient_key = self.recipient_key(environment, &recipient).await?;
        let actor = &context.audit_principal();
        self.audit(actor, "plan.identity_issuer.rewrap.requested")?;
        let mut ctx = self.catalog_ctx(&context)?;
        let env_obj = crate::environment::environment(&mut ctx, environment)
            .await
            .map_err(map_plan_lifecycle_error)?;
        let step = crate::identity_issuer::rewrap_step(&env_obj, &recipient_key)
            .map_err(map_plan_lifecycle_error)?
            .ok_or_else(|| {
                ManagementError::BadRequest(format!("{environment} has no identity issuer"))
            })?;
        let stored = crate::plan::create_from_steps(&mut ctx, environment, vec![step])
            .await
            .map_err(map_plan_lifecycle_error)?;
        self.audit(actor, "plan.identity_issuer.rewrap.completed")?;
        let digest = format!(
            "sha256:{}",
            stored
                .executable_digest()
                .map_err(map_plan_lifecycle_error)?
        );
        Ok(ManagementLifecycleResult::new(
            ManagementLifecycleOperation::Plan,
            format!(
                "identity issuer re-wrap plan {} for {recipient} requires signed approval",
                stored.id
            ),
            Some(stored.id),
        )
        .with_digest(digest))
    }

    async fn admit_identity_issuer(
        &self,
        credential: &CredentialMaterial,
        environment: &str,
        request: &PlanRequest,
    ) -> Result<AuthenticatedRequestContext, ManagementError> {
        let context = self.authenticate(credential)?;
        self.admit_agent_plan(&context, "plan.identity_issuer")?;
        Self::require_capability(&context, DeliveryCapability::Management)?;
        management_lifecycle::admit_plan(
            request,
            environment,
            context.principal.kind,
            self.granted_environment(credential, &context),
        )
        .map_err(map_lifecycle_error)?;
        self.require_environment_visible(&context, environment)
            .await?;
        self.require_current_generation(&context, environment, request.expected_generation)
            .await?;
        Ok(context)
    }
}
