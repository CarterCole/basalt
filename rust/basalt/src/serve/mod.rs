//! The interop surfaces, PROTOCOL §17 and `protocol/INTEROP.md`.
//!
//! §12 defines one HTTP read surface. This module serves the same vault as
//! REST with an OpenAPI 3.1 document (profile `P-REST`) and over the Model
//! Context Protocol on HTTP and stdio (profile `P-MCP`), both through the one
//! enforcement point in [`surface::Surface`] (INTEROP §1.1).

pub mod jsonrpc;
pub mod mcp;
pub mod ops;
pub mod rest;
pub mod router;
pub mod surface;

pub use router::{Router, SurfaceKind};
pub use surface::{Delivery, Fault, Surface};
