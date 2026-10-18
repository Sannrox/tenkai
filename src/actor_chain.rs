//! Delegating actors from a verified token's `act` claim.
//!
//! A tool gateway that calls Tenkai for an AI agent sends the user as `sub`
//! and the agent in `act`. Verifiers parse `act` into an [`Actor`] chain, and
//! management operations refuse or hold mutations whose chain names an agent.

use serde::{Deserialize, Serialize};

use crate::auth_context::AuthError;

/// Longest accepted `act` nesting. Deeper chains fail closed.
pub const MAX_ACTOR_CHAIN_DEPTH: usize = 8;

/// One actor that called on behalf of the token subject, outermost first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub id: String,
    pub kind: ActorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// The token says this actor is a person.
    Human,
    /// Anything else, including an actor whose kind the token does not state.
    Agent,
}

/// Parse a verified `act` claim.
///
/// Accepts a string actor id, or an object `{"sub": id, "kind"?: k, "act"?: ...}`
/// nested as in token exchange. Only `kind: "human"` counts as a person; a
/// bare string or any other kind is an agent, so an unlabelled actor never
/// gets human authority. Empty ids, repeated actors, and chains deeper than
/// [`MAX_ACTOR_CHAIN_DEPTH`] are rejected.
pub fn parse_actor_chain(claim: &serde_json::Value) -> Result<Vec<Actor>, AuthError> {
    let invalid = |detail: &str| AuthError::Unauthorized(format!("invalid act claim: {detail}"));
    let mut chain: Vec<Actor> = Vec::new();
    let mut next = Some(claim);
    while let Some(value) = next {
        if chain.len() == MAX_ACTOR_CHAIN_DEPTH {
            return Err(invalid("actor chain is too deep"));
        }
        let (id, kind, nested) = match value {
            serde_json::Value::String(id) => (id.as_str(), ActorKind::Agent, None),
            serde_json::Value::Object(fields) => {
                let id = fields
                    .get("sub")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| invalid("actor object needs a string sub"))?;
                let kind = match fields.get("kind") {
                    None => ActorKind::Agent,
                    Some(serde_json::Value::String(kind)) if kind == "human" => ActorKind::Human,
                    Some(serde_json::Value::String(_)) => ActorKind::Agent,
                    Some(_) => return Err(invalid("actor kind must be a string")),
                };
                (id, kind, fields.get("act"))
            }
            _ => return Err(invalid("actor must be a string or an object")),
        };
        let id = id.trim();
        if id.is_empty() {
            return Err(invalid("actor id must not be empty"));
        }
        if chain.iter().any(|actor| actor.id == id) {
            return Err(invalid("actor chain repeats an actor"));
        }
        chain.push(Actor {
            id: id.to_string(),
            kind,
        });
        next = nested;
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn string_and_unlabelled_actors_are_agents() {
        let chain = parse_actor_chain(&json!("assistant-1")).unwrap();
        assert_eq!(chain[0].kind, ActorKind::Agent);
        let chain = parse_actor_chain(&json!({"sub": "assistant-1"})).unwrap();
        assert_eq!(chain[0].kind, ActorKind::Agent);
    }

    #[test]
    fn nested_chain_keeps_order_and_kinds() {
        let chain = parse_actor_chain(&json!({
            "sub": "gateway",
            "kind": "service",
            "act": {"sub": "operator-2", "kind": "human"}
        }))
        .unwrap();
        assert_eq!(
            chain,
            [
                Actor {
                    id: "gateway".into(),
                    kind: ActorKind::Agent
                },
                Actor {
                    id: "operator-2".into(),
                    kind: ActorKind::Human
                },
            ]
        );
    }

    #[test]
    fn malformed_chains_fail_closed() {
        for claim in [
            json!(""),
            json!(42),
            json!({"kind": "human"}),
            json!({"sub": "a", "kind": 1}),
            json!({"sub": "a", "act": {"sub": "a"}}),
        ] {
            assert!(parse_actor_chain(&claim).is_err(), "{claim}");
        }
        let mut deep = json!("leaf");
        for depth in 0..MAX_ACTOR_CHAIN_DEPTH {
            deep = json!({"sub": format!("actor-{depth}"), "act": deep});
        }
        assert!(parse_actor_chain(&deep).is_err());
    }
}
