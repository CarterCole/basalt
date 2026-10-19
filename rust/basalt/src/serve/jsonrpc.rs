//! JSON-RPC 2.0 framing, INTEROP §4.1.
//!
//! Kept separate from MCP because the framing is not MCP's: the same method
//! table shape serves a plain JSON-RPC endpoint, and the stdio loop below is
//! what an MCP client spawning a process speaks.

use crate::canonical::{parse_json, Json};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Json>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(code: i64, message: impl Into<String>, data: Json) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }
}

/// A handler for one method. `None` as a return is not an option: a
/// notification is recognized by the *request* having no id, not by the
/// handler declining to answer.
pub type Handler<'a> = Box<dyn Fn(&Json) -> Result<Json, RpcError> + Send + Sync + 'a>;

#[derive(Default)]
pub struct Methods<'a> {
    map: BTreeMap<String, Handler<'a>>,
}

impl<'a> Methods<'a> {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn on(
        mut self,
        name: &str,
        f: impl Fn(&Json) -> Result<Json, RpcError> + Send + Sync + 'a,
    ) -> Self {
        self.map.insert(name.to_string(), Box::new(f));
        self
    }

    pub fn names(&self) -> Vec<&str> {
        self.map.keys().map(String::as_str).collect()
    }

    /// Dispatch one parsed message. `None` means the message was a
    /// notification, and a notification MUST NOT be answered.
    pub fn dispatch(&self, msg: &Json) -> Option<Json> {
        let Json::Object(fields) = msg else {
            return Some(error(Json::Null, INVALID_REQUEST, "not a JSON-RPC object"));
        };
        let id = fields.get("id").cloned();
        let notification = id.is_none();
        let reply = |value: Json| -> Option<Json> {
            if notification {
                None
            } else {
                Some(value)
            }
        };
        let id_or_null = id.clone().unwrap_or(Json::Null);

        if fields.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return reply(error(id_or_null, INVALID_REQUEST, "jsonrpc must be \"2.0\""));
        }
        // A response flowing back in is not ours to answer.
        if fields.contains_key("result") || fields.contains_key("error") {
            return None;
        }
        let Some(method) = fields.get("method").and_then(|v| v.as_str()) else {
            return reply(error(id_or_null, INVALID_REQUEST, "method is required"));
        };
        let Some(handler) = self.map.get(method) else {
            return reply(error(
                id_or_null,
                METHOD_NOT_FOUND,
                format!("unknown method {method}"),
            ));
        };
        let params = fields.get("params").cloned().unwrap_or(Json::obj().build());
        match handler(&params) {
            Ok(value) => reply(result(id_or_null, value)),
            Err(e) => reply(match e.data {
                Some(data) => error_with_data(id_or_null, e.code, e.message, data),
                None => error(id_or_null, e.code, e.message),
            }),
        }
    }

    /// Parse, dispatch, and return the text to write back, or `None` when
    /// nothing is owed — a notification, or a batch of them.
    pub fn handle_text(&self, text: &str) -> Option<String> {
        let parsed = match parse_json(text) {
            Ok(v) => v,
            Err(_) => {
                return Some(
                    error(Json::Null, PARSE_ERROR, "invalid JSON").to_compact_string(),
                )
            }
        };
        if let Json::Array(batch) = parsed {
            let answers: Vec<Json> = batch.iter().filter_map(|m| self.dispatch(m)).collect();
            if answers.is_empty() {
                return None;
            }
            return Some(Json::Array(answers).to_compact_string());
        }
        self.dispatch(&parsed).map(|r| r.to_compact_string())
    }

    /// Run a newline-delimited JSON-RPC loop over stdin and stdout — the
    /// stdio transport MCP clients spawn.
    ///
    /// Nothing but JSON-RPC may go to stdout, so every diagnostic in this path
    /// belongs on stderr.
    pub fn serve_stdio(&self) -> std::io::Result<()> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Some(answer) = self.handle_text(&line) {
                stdout.write_all(answer.as_bytes())?;
                stdout.write_all(b"\n")?;
                stdout.flush()?;
            }
        }
        Ok(())
    }
}

pub fn result(id: Json, value: Json) -> Json {
    Json::obj()
        .set("jsonrpc", Json::str("2.0"))
        .set("id", id)
        .set("result", value)
        .build()
}

pub fn error(id: Json, code: i64, message: impl Into<String>) -> Json {
    Json::obj()
        .set("jsonrpc", Json::str("2.0"))
        .set("id", id)
        .set(
            "error",
            Json::obj()
                .set("code", Json::Int(code))
                .set("message", Json::str(message.into()))
                .build(),
        )
        .build()
}

pub fn error_with_data(id: Json, code: i64, message: impl Into<String>, data: Json) -> Json {
    Json::obj()
        .set("jsonrpc", Json::str("2.0"))
        .set("id", id)
        .set(
            "error",
            Json::obj()
                .set("code", Json::Int(code))
                .set("message", Json::str(message.into()))
                .set("data", data)
                .build(),
        )
        .build()
}
