//! The terminal stream of a debug session (ADR 0061 §7, #1558).
//!
//! An operator and the runtime that owns the session each open a WebSocket
//! with subprotocol [`STREAM_PROTOCOL`]; the server relays frames between
//! them and stores none. Binary frames carry terminal I/O. Text frames carry
//! one JSON [`Control`] each.

use serde::{Deserialize, Serialize};

/// The WebSocket subprotocol both ends must request.
pub const STREAM_PROTOCOL: &str = "tenkai.debug-stream.v1";

/// What a runtime answers for an executor it cannot attach a terminal to.
pub const UNSUPPORTED_MESSAGE: &str = "not supported for this executor";

/// A control message, one per text frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Control {
    /// Server to both ends: the other end is connected.
    Attached,
    /// Operator to runtime: the terminal size changed.
    Resize { cols: u16, rows: u16 },
    /// Operator to runtime: one command line to run.
    Command { command: String },
    /// Runtime to operator: the command or shell exited.
    Exit { code: i32 },
    /// Either way, last frame before the WebSocket closes.
    Close {
        reason: CloseReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

/// Why a stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// The other end closed.
    PeerClosed,
    /// The session reached `not_after`.
    BoundReached,
    /// The session was closed or expired.
    SessionClosed,
    /// A credential or grant of either end no longer admits the stream.
    GrantRevoked,
    /// A newer connection of the same end took over.
    Replaced,
    /// The runtime cannot attach a terminal to this instance's executor.
    Unsupported,
    /// A frame broke this protocol, or the relay could not keep up.
    ProtocolError,
}

impl Control {
    /// A close with `reason` and no message.
    pub fn close(reason: CloseReason) -> Self {
        Self::Close {
            reason,
            message: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_are_tagged_json() {
        let close = Control::Close {
            reason: CloseReason::Unsupported,
            message: Some(UNSUPPORTED_MESSAGE.into()),
        };
        let json = serde_json::to_string(&close).unwrap();
        assert_eq!(
            json,
            r#"{"type":"close","reason":"unsupported","message":"not supported for this executor"}"#
        );
        assert_eq!(serde_json::from_str::<Control>(&json).unwrap(), close);
        assert!(serde_json::from_str::<Control>(r#"{"type":"shell"}"#).is_err());
    }
}
