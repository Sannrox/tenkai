//! Closed Product-kind policy shared by manifest admission, planning, and apply.
//!
//! Product kinds are a closed vocabulary, so this module deliberately avoids a
//! trait seam. One exhaustive mapping owns target selection, cleanup semantics,
//! staged-document identity, and coordinated model/routing rollout rank.

use crate::manifest::ProductKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProductTarget {
    Software,
    RoutingConfig,
    ModelRuntime,
    WorkerPool,
    Staged(StagedKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StagedKind {
    PolicyBundle,
    EvalSuite,
    AgentDefinition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupPolicy {
    Atomic,
    UninstallIfDeclared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RolloutDirection {
    Forward,
    Reverse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProductKindPolicy {
    target: ProductTarget,
}

impl ProductKind {
    pub(crate) const fn policy(self) -> ProductKindPolicy {
        let target = match self {
            Self::Software => ProductTarget::Software,
            Self::RoutingConfig => ProductTarget::RoutingConfig,
            Self::ModelRuntime => ProductTarget::ModelRuntime,
            Self::WorkerPool => ProductTarget::WorkerPool,
            Self::PolicyBundle => ProductTarget::Staged(StagedKind::PolicyBundle),
            Self::EvalSuite => ProductTarget::Staged(StagedKind::EvalSuite),
            Self::AgentDefinition => ProductTarget::Staged(StagedKind::AgentDefinition),
        };
        ProductKindPolicy { target }
    }
}

impl ProductKindPolicy {
    pub(crate) const fn target(self) -> ProductTarget {
        self.target
    }

    pub(crate) const fn staged_kind(self) -> Option<StagedKind> {
        match self.target {
            ProductTarget::Staged(kind) => Some(kind),
            _ => None,
        }
    }

    pub(crate) const fn cleanup(self) -> CleanupPolicy {
        match self.target {
            ProductTarget::Software => CleanupPolicy::UninstallIfDeclared,
            ProductTarget::RoutingConfig
            | ProductTarget::ModelRuntime
            | ProductTarget::WorkerPool
            | ProductTarget::Staged(_) => CleanupPolicy::Atomic,
        }
    }

    pub(crate) const fn rollout_rank(self, direction: RolloutDirection) -> u8 {
        match (self.target, direction) {
            (ProductTarget::ModelRuntime, RolloutDirection::Forward)
            | (ProductTarget::RoutingConfig, RolloutDirection::Reverse) => 0,
            (ProductTarget::RoutingConfig, RolloutDirection::Forward)
            | (ProductTarget::ModelRuntime, RolloutDirection::Reverse) => 1,
            _ => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_exhaustively_classifies_every_product_kind() {
        let cases = [
            (ProductKind::Software, ProductTarget::Software, false),
            (
                ProductKind::RoutingConfig,
                ProductTarget::RoutingConfig,
                true,
            ),
            (ProductKind::ModelRuntime, ProductTarget::ModelRuntime, true),
            (ProductKind::WorkerPool, ProductTarget::WorkerPool, true),
            (
                ProductKind::PolicyBundle,
                ProductTarget::Staged(StagedKind::PolicyBundle),
                true,
            ),
            (
                ProductKind::EvalSuite,
                ProductTarget::Staged(StagedKind::EvalSuite),
                true,
            ),
            (
                ProductKind::AgentDefinition,
                ProductTarget::Staged(StagedKind::AgentDefinition),
                true,
            ),
        ];
        for (kind, target, atomic) in cases {
            let policy = kind.policy();
            assert_eq!(policy.target(), target);
            assert_eq!(
                policy.staged_kind().is_some(),
                matches!(target, ProductTarget::Staged(_))
            );
            assert_eq!(policy.cleanup() == CleanupPolicy::Atomic, atomic);
        }
    }

    #[test]
    fn rollout_rank_keeps_model_and_routing_products_distinct() {
        assert!(
            ProductKind::ModelRuntime
                .policy()
                .rollout_rank(RolloutDirection::Forward)
                < ProductKind::RoutingConfig
                    .policy()
                    .rollout_rank(RolloutDirection::Forward)
        );
        assert!(
            ProductKind::RoutingConfig
                .policy()
                .rollout_rank(RolloutDirection::Reverse)
                < ProductKind::ModelRuntime
                    .policy()
                    .rollout_rank(RolloutDirection::Reverse)
        );
    }
}
