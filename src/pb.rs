//! Generated gRPC bindings for the vendored sekai-chisei protos.
//!
//! The protos in `proto/vendor/` are copied verbatim from the sekai-chisei
//! repository; tenkai is a pure client of that contract.

pub mod sekai {
    tonic::include_proto!("sekai");
}

pub mod chisei {
    tonic::include_proto!("chisei");
}

/// Version 1 of the planner/agent wire contract.
pub mod agent_v1 {
    /// Value required in every version 1 request and response envelope.
    pub const PROTOCOL_VERSION: u32 = 1;

    tonic::include_proto!("tenkai.agent.v1");
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::agent_v1::{
        PlanReference, PlanState, PullPlanRequest, PullPlanResponse, ReportPlanTransitionRequest,
        ReportPlanTransitionResponse,
    };

    #[test]
    fn agent_v1_ignores_unknown_additive_fields() {
        let request = PullPlanRequest {
            protocol_version: 1,
            agent_id: "agent-a".into(),
            environment_id: "tenkai.environment:prod".into(),
            last_seen_plan_id: "tenkai.plan:prior".into(),
        };
        let mut encoded = request.encode_to_vec();

        // Future field 100, encoded as a varint. Proto3 readers must skip it.
        encoded.extend_from_slice(&[0xa0, 0x06, 0x07]);

        assert_eq!(
            PullPlanRequest::decode(encoded.as_slice()).unwrap(),
            request
        );
    }

    #[test]
    fn agent_v1_preserves_unknown_enum_values() {
        let transition = ReportPlanTransitionRequest {
            protocol_version: 1,
            plan_id: "tenkai.plan:durable".into(),
            transition_id: "transition-1".into(),
            from_state: PlanState::Running.into(),
            to_state: 99,
            observed_at_unix_ms: 1,
            detail: String::new(),
        };

        let decoded =
            ReportPlanTransitionRequest::decode(transition.encode_to_vec().as_slice()).unwrap();

        assert_eq!(decoded.to_state, 99);
    }

    #[test]
    fn agent_v1_state_numbers_are_stable() {
        assert_eq!(PlanState::Unspecified as i32, 0);
        assert_eq!(PlanState::Computed as i32, 1);
        assert_eq!(PlanState::Running as i32, 2);
        assert_eq!(PlanState::Blocked as i32, 3);
        assert_eq!(PlanState::Succeeded as i32, 4);
        assert_eq!(PlanState::Failed as i32, 5);
    }

    #[test]
    fn agent_v1_message_wire_layout_is_stable() {
        let plan = PlanReference {
            plan_id: "p".into(),
            environment_id: "e".into(),
            plan_format_version: 1,
        };
        assert_eq!(plan.encode_to_vec(), hex("0a01701201651801"));

        let pull = PullPlanRequest {
            protocol_version: 1,
            agent_id: "a".into(),
            environment_id: "e".into(),
            last_seen_plan_id: "p".into(),
        };
        assert_eq!(pull.encode_to_vec(), hex("08011201611a0165220170"));

        let pulled = PullPlanResponse {
            protocol_version: 1,
            plan: Some(plan),
        };
        assert_eq!(pulled.encode_to_vec(), hex("080112080a01701201651801"));

        let report = ReportPlanTransitionRequest {
            protocol_version: 1,
            plan_id: "p".into(),
            transition_id: "t".into(),
            from_state: PlanState::Running.into(),
            to_state: PlanState::Succeeded.into(),
            observed_at_unix_ms: 1,
            detail: "d".into(),
        };
        assert_eq!(
            report.encode_to_vec(),
            hex("08011201701a01742002280430013a0164")
        );

        let reported = ReportPlanTransitionResponse {
            protocol_version: 1,
            plan_id: "p".into(),
            transition_id: "t".into(),
            accepted: true,
            current_state: PlanState::Running.into(),
            rejection_reason: "r".into(),
        };
        assert_eq!(
            reported.encode_to_vec(),
            hex("08011201701a017420012802320172")
        );
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
