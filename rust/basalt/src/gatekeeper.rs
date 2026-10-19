//! The gatekeeper HTTP service, PROTOCOL §12.
//!
//! This process holds the only credentials to the store. The bucket stays
//! private and never faces the reader, which is what makes §8's inherited
//! permissions real rather than advisory — no S3-like store can express an
//! inherited deny, so something has to stand in front of it.
//!
//! The server is hand-rolled over `TcpListener` rather than built on an async
//! HTTP stack. The surfaces it serves are read-only routes over a synchronous
//! transport; an executor would add a dependency tree larger than this entire
//! crate without changing what any route returns.
//!
//! The routes themselves live in [`crate::serve`]: the §12.3 read surface is
//! one of several protocols mounted on the same principal-scoped view of the
//! vault (INTEROP §1.1), and this module is the listener plus the one identity
//! step (§12.1).

use crate::serve::router::{Router, SurfaceKind};
use crate::serve::surface::Surface;
use crate::vault::{IndexState, Vault};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

pub use crate::serve::router::{Request, Response};
/// Re-exported so `use basalt::gatekeeper::Delivery` keeps working now that
/// the mode belongs to the surface every protocol shares.
pub use crate::serve::surface::Delivery;

/// Reduces a request to exactly one principal id (§12.1).
///
/// How that happens is out of scope — session cookie, OIDC, signed token,
/// mTLS, a reverse-proxy header. The one hard rule is that a client MUST NOT
/// be able to assert its own principal id, so this takes the raw headers and
/// the implementor decides which of them, if any, is trustworthy.
pub type Identify = Arc<dyn Fn(&Request) -> String + Send + Sync>;

pub struct Gatekeeper {
    router: Router,
    identify: Identify,
}

impl Gatekeeper {
    pub fn new(vault: Vault) -> Self {
        Self {
            router: Router::new(Surface::new(vault)),
            // The default returns `anonymous` for everything: authentication
            // is deliberately out of scope (§12.1).
            identify: Arc::new(|_| "anonymous".to_string()),
        }
    }

    pub fn with_identify(mut self, f: Identify) -> Self {
        self.identify = f;
        self
    }

    pub fn with_delivery(mut self, d: Delivery) -> Self {
        self.router.surface.set_delivery(d);
        self
    }

    /// Mount a subset of the surfaces the vault declares (INTEROP §10).
    pub fn with_surfaces(mut self, surfaces: BTreeSet<SurfaceKind>) -> Self {
        self.router = self.router.with_surfaces(surfaces);
        self
    }

    /// Force one principal for every request — for local testing only.
    pub fn with_fixed_principal(self, who: &str) -> Self {
        let who = who.to_string();
        self.with_identify(Arc::new(move |_| who.clone()))
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    pub fn surface(&self) -> &Surface {
        &self.router.surface
    }

    pub fn set_index_state(&self, state: IndexState) {
        self.router.surface.set_index_state(state);
    }

    /// Drop cached index-derived responses; call after a reindex.
    pub fn invalidate(&self) {
        self.router.surface.invalidate();
    }

    /// Handle a request with no body — every GET route.
    pub fn handle(&self, req: &Request) -> Response {
        self.handle_with_body(req, &[])
    }

    /// Handle a request, body included: the method-call surfaces POST one.
    pub fn handle_with_body(&self, req: &Request, body: &[u8]) -> Response {
        // Identity is resolved here and exactly once (§12.1), before any
        // surface sees the request, so no surface can be talked into
        // accepting a client-asserted principal.
        let principal = (self.identify)(req);
        self.router.handle(&principal, req, body)
    }

    /// Serve until the process ends.
    pub fn listen(self: Arc<Self>, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        self.serve(listener);
        Ok(())
    }

    /// Bind without serving, so a caller can report the real port.
    pub fn bind(addr: &str) -> std::io::Result<TcpListener> {
        TcpListener::bind(addr)
    }

    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let me = Arc::clone(&self);
            std::thread::spawn(move || {
                let _ = me.serve_one(stream);
            });
        }
    }

    fn serve_one(&self, mut stream: TcpStream) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut start = String::new();
        if reader.read_line(&mut start)? == 0 {
            return Ok(());
        }
        let mut parts = start.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_string();
        let raw_target = parts.next().unwrap_or("/").to_string();

        let mut headers = BTreeMap::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        // Read the body rather than draining it: /mcp is a POST surface. The
        // cap is there because every surface here answers a query, so a large
        // body is a mistake or an attack, not a request (INTEROP §1.5).
        let declared = headers
            .get("content-length")
            .and_then(|l| l.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; declared.min(crate::serve::router::MAX_BODY)];
        if !body.is_empty() {
            reader.read_exact(&mut body)?;
        }
        if declared > crate::serve::router::MAX_BODY {
            // Drain the rest so the connection closes cleanly, then let the
            // router answer with the fault.
            let mut sink = vec![0u8; declared - crate::serve::router::MAX_BODY];
            let _ = reader.read_exact(&mut sink);
            body = vec![0u8; crate::serve::router::MAX_BODY + 1];
        }

        let (path, query) = match raw_target.split_once('?') {
            Some((p, q)) => (p.to_string(), parse_query(q)),
            None => (raw_target.clone(), BTreeMap::new()),
        };

        let resp = self.handle_with_body(
            &Request {
                method: method.clone(),
                path,
                query,
                headers,
            },
            &body,
        );

        let reason = match resp.status {
            200 => "OK",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Content Too Large",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Error",
        };
        let mut head = format!("HTTP/1.1 {} {reason}\r\n", resp.status);
        for (k, v) in &resp.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!("content-length: {}\r\n", resp.body.len()));
        head.push_str("connection: close\r\n\r\n");
        stream.write_all(head.as_bytes())?;
        // A HEAD response carries the headers of the GET and none of the body.
        if method != "HEAD" {
            stream.write_all(&resp.body)?;
        }
        stream.flush()
    }
}

fn parse_query(q: &str) -> BTreeMap<String, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (
                crate::serve::rest::percent_decode(k),
                crate::serve::rest::percent_decode(&v.replace('+', " ")),
            ),
            None => (crate::serve::rest::percent_decode(p), String::new()),
        })
        .collect()
}
