# The Basalt Interoperability Annex, v1

This annex is normative. It specifies the protocols a Basalt gatekeeper MAY
speak in addition to the §12 read surface, and — more importantly — what all
of them MUST have in common.

The main spec ([PROTOCOL.md](PROTOCOL.md)) is cited as §n. This annex is cited
as INTEROP §n. Where the two conflict, PROTOCOL.md wins.

## 0. Why a vault speaks more than one protocol

A vault is a *format*, so the useful question is not "what is our API" but
"what can already read this". The answer differs by client: an agent wants
MCP, a web app wants GraphQL or REST, a generated client wants protobuf, a
reader wants a folder they can mount, an aggregator wants Atom, a triple store
wants Turtle. None of them should have to be told about the other six.

The cost of eight protocols is eight chances to get §8 wrong. That cost is
contained by one structural rule, §1.1, and then verified by one test suite,
§9: **a surface is a translation layer with no behaviour of its own.**

## 1. The surface core

### 1.1 Every protocol goes through one object

An implementation serving more than one protocol MUST route every protocol
through a single principal-scoped view of the vault, and that view MUST be the
only thing that touches the store or the ACL evaluator.

Concretely, these MUST be implemented once, below every surface:

- §8.4 evaluation for the requesting principal,
- the §12.3 404/403 split,
- the §12.4 withheld trees (`meta/`, `index/`, `principals/`, `history/`,
  `basalt.yaml`),
- the §12.5 cache keyed by the principal's effective subject set,
- the §12.2 audience ceiling.

An implementation MUST NOT re-derive any of them per surface. The reference
implementation puts this in `ts/src/serve/core.mjs`; a surface that reaches
past it into the vault is a defect even when its output is correct, because
the next surface written by copying it will not be.

Identity is resolved exactly once per request, before dispatch (§12.1). A
surface MUST NOT read a principal id out of a request body, a GraphQL
variable, an MCP parameter, a proto field or a DAV header.

### 1.2 The operation table

Every method-call surface (JSON-RPC, MCP tools, gRPC/Connect) MUST expose the
same operations, with the same arguments and the same results:

| Operation | Arguments | Returns |
|---|---|---|
| `manifest` | — | the public manifest subset (§3.1) |
| `me` | — | the principal and its subject set (§8.4) |
| `node` | `path`, `include_text?`, `include_bytes?` | entry, text, media type, edges |
| `list` | `folder` | direct entries and subfolders |
| `nodes` | `limit?`, `offset?`, `published?` | readable entries in §13.3 order |
| `links` | `path` | out-edges and backlinks, redacted per §9.5 |
| `search` | `q`, `limit?`, `offset?` | postings over readable nodes |
| `tree` | — | the visible tree |
| `tags` | — | tags and their readable nodes |
| `recent` | `limit?`, `published?` | readable entries by store mtime |
| `effective` | `path`, `principal?` | effective rights, needs `read_acl` (§8.7) |

Naming per surface is mechanical and MUST follow these rules, so that one
table yields every spelling: JSON-RPC `basalt.<operation>`, MCP tool
`basalt_<operation>`, gRPC method `<PascalCase verb>` as declared in
[basalt.proto](basalt.proto).

An operation MUST NOT exist on one method-call surface and not another.
Surface-shaped conveniences (REST's `raw` route, GraphQL's lazy `Node.text`)
are permitted, because they return the same data differently rather than
different data.

### 1.3 Faults

A denial carries the same meaning everywhere and MUST be translated, not
reinterpreted:

| Fault | HTTP | Connect/gRPC | JSON-RPC | GraphQL `extensions.code` |
|---|---|---|---|---|
| `not_found` | 404 | `not_found` | −32004 | `not_found` |
| `forbidden` | 403 | `permission_denied` | −32003 | `forbidden` |
| `unauthenticated` | 401 | `unauthenticated` | −32001 | `unauthenticated` |
| `bad_request` | 400 | `invalid_argument` | −32602 | `bad_request` |
| `method_not_allowed` | 405 | `unimplemented` | −32601 | `method_not_allowed` |
| `internal` | 500 | `internal` | −32603 | `internal` |

`not_found` MUST remain ambiguous between "no such object" and "you may not
discover it" on every surface (§12.3). A surface MUST NOT add a field, a
message, a count or a timing difference that distinguishes them.

MCP is the one exception to "a fault is an error": a denial raised by
`tools/call` MUST be returned as a tool *result* with `isError: true`, because
the caller is a model that needs to read the answer. `resources/read` MUST
still fail as a JSON-RPC error.

### 1.4 Discovery

A multi-protocol gatekeeper MUST serve a discovery document at
`/.well-known/basalt` describing only the surfaces it actually mounts. It is
the one response that is identical for every principal, and it MUST therefore
describe surfaces and never content.

```
GET /.well-known/basalt
{
  "basalt": 1,
  "vault": {"id": "01J…", "title": "…"},
  "publish": {"audience": "gated", "home": "…"},
  "operations": ["manifest", "me", "node", …],
  "surfaces": {"rest": {…}, "graphql": {…}, "mcp": {…}, …}
}
```

A surface that is switched off MUST be absent from the document and MUST 404,
so that "off" and "broken" are distinguishable.

### 1.5 Rules every surface obeys

1. **Read-only.** §12 defines a read surface. A write surface needs §11
   history semantics and §8's `write`/`create_child` evaluation, and is out of
   scope for v1. Every surface MUST refuse mutating requests: HTTP 405,
   `unimplemented`, or a GraphQL schema with no `Mutation` type.
2. **No shared caching.** Every per-principal response MUST carry
   `Cache-Control: private, no-store` and MUST vary on whatever carried the
   identity. A validator (ETag) over a derived response MUST depend on the
   subject set, or a shared cache will serve one principal's view to another.
3. **No sniffing.** Responses carrying author-supplied bytes MUST send
   `X-Content-Type-Options: nosniff`.
4. **Freshness.** Every response SHOULD carry `X-Basalt-Index-State`
   (§10.6) and `X-Basalt-Vault`.
5. **No presigned URL in a body.** A presigned URL is a bearer token that
   outlives the ACL check that produced it (§12.4). It MAY be a `302 Location`
   in `redirect` delivery mode; it MUST NOT appear in a JSON field, a GraphQL
   scalar, an RDF literal or a feed entry.
6. **Bounded request bodies.** Every surface here answers queries, so an
   implementation MUST cap request bodies (the reference caps at 1 MiB).
7. **Path precedence.** Where a protocol route and a node's own URL could
   collide, the protocol route wins, and an implementation SHOULD say so (a
   vault with a root node named `feed.xml` reaches it through
   `/api/v1/node/feed.xml`).

## 2. REST (OpenAPI 3.1)

The §12.3 routes, plus `me`, `nodes`, `tags` and `openapi.json`.

- The service MUST serve an OpenAPI 3.1 document describing every route it
  serves, including the 403 and 404 responses, and it SHOULD generate it from
  the same table that dispatches requests.
- Errors MUST be RFC 9457 problem documents (`application/problem+json`) with
  `type: urn:basalt:problem:<fault>`. The member `error` repeats the fault code
  for clients written against the pre-annex surface.
- `ETag`/`If-None-Match` MUST be supported on JSON routes, subject to §1.5.2.
- `HEAD` MUST return the headers of the corresponding `GET` with no body.

## 3. GraphQL

- The service MUST serve its SDL at `/graphql/schema.graphql`, and the SDL is
  the cross-language artifact: another implementation serves the same schema
  with whatever library it likes.
- The schema MUST have no `Mutation` and no `Subscription` type.
- `GET /graphql?query=` is permitted here precisely because every operation is
  a query.
- A denial MUST be a field error: the field resolves to `null`, the `errors`
  entry carries `path` and `extensions.code`, and the HTTP status stays 200. A
  query asking for twenty nodes of which nineteen are readable MUST return
  nineteen.
- Introspection MUST be sufficient for client codegen (`__schema`, `__type`,
  `__typename`, field args, enum values, directives).

The reference implementation's executor supports queries, variables, aliases,
named and inline fragments and `@skip`/`@include`. It does not implement
interfaces, unions, input objects, custom directives or subscriptions, none of
which this schema uses. A conforming implementation MAY use a full GraphQL
library instead; the SDL is the contract.

## 4. Method-call surfaces

### 4.1 JSON-RPC 2.0

`POST /rpc`, methods `basalt.<operation>` (§1.2), plus `basalt.operations`
which describes the table. Notifications (no `id`) MUST get no response.
Batch arrays SHOULD be accepted.

### 4.2 Model Context Protocol

`POST /mcp` for Streamable HTTP, and a stdio transport for clients that spawn
a process.

- **Tools** MUST be the operation table (§1.2) with `basalt_` prefixes, each
  carrying a JSON Schema for its arguments and a description.
- **Resources** MUST be the readable nodes, with URIs
  `basalt://<vault-id>/<percent-encoded path>`. A `resources/read` whose
  authority names another vault MUST fail rather than fall through to this
  one: a client holding several vaults open must not cross them.
- A text node is returned as `text`; any other kind as base64 `blob`.
- `resources/list` MUST paginate with `cursor`/`nextCursor`.
- Denials follow §1.3, including the `tools/call` exception.
- The server MUST declare only the capabilities it has. The reference declares
  `tools` and `resources`, with neither `subscribe` nor `listChanged`, and
  opens no SSE stream — it has no server-initiated messages to send.

#### 4.2.1 Version negotiation

The server MUST answer `initialize` with a version it actually speaks: the
client's requested version when supported, otherwise the server's latest.
Echoing an unsupported version back is forbidden — it converts a handshake
failure into a mystery later.

On stdio, **stdout carries JSON-RPC and nothing else**. Diagnostics go to
stderr.

## 5. gRPC and Connect

[basalt.proto](basalt.proto) is the schema: service `basalt.v1.BasaltRead`,
one unary method per operation.

- Every multi-word proto field MUST set `json_name` to its own snake_case
  name. This overrides proto3 JSON's lowerCamelCase default and is what makes
  a Connect JSON response byte-identical to the REST response for the same
  operation — which is what lets §9 compare them directly.
- Rights, kinds and decisions MUST be `string`, not proto enums: the
  protocol's vocabulary (§8.1, §5.1) is lowercase, proto enum JSON names are
  not, and a string keeps a value from a newer vault readable.
- Error codes follow §1.3.

An implementation MAY serve Connect-over-HTTP/1.1 with the JSON codec only,
as the reference does, provided it answers an unsupported codec with
`unimplemented` and says so. Binary gRPC and gRPC-Web require HTTP/2 or a
Connect-aware proxy.

## 6. WebDAV

A read-only DAV class 1 mount at `/dav/`. This is the surface that gets an
ACL-filtered vault into a Finder window, `rclone`, or `davfs2`, after which
every file-reading tool works on the subset the principal may read — while the
gatekeeper keeps the only credentials to the bucket.

- `OPTIONS` MUST advertise `DAV: 1` and an `Allow` of
  `OPTIONS, GET, HEAD, PROPFIND`.
- `PROPFIND` MUST support `Depth: 0` and `Depth: 1`, MAY support `infinity`,
  and MUST omit every node the principal cannot read. Omission, not 403: a
  directory listing that reports a forbidden child discloses it.
- Properties: `resourcetype`, `displayname`, `getcontentlength`,
  `getcontenttype`, `getetag`, `getlastmodified`. A requested property the
  server does not have MUST come back in a `404` propstat rather than being
  silently dropped.
- Every write method (`PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`, `PROPPATCH`,
  `LOCK`, `UNLOCK`) MUST return 405 (§1.5.1). Class 2 is therefore not
  claimed: a server with no write path has no use for `LOCK`.
- The withheld trees MUST NOT be mountable (§12.4).

## 7. Syndication and discovery

| Route | Format |
|---|---|
| `/feed.atom` | Atom 1.0 |
| `/feed.xml` | RSS 2.0 |
| `/sitemap.xml` | sitemaps.org 0.9 |
| `/opensearch.xml` | OpenSearch 1.1 |
| `/robots.txt` | robots exclusion |

- Entries MUST be readable nodes with `publish` unset or true, newest first by
  store mtime. Store mtime is presentation only here; §1 forbids relying on it
  for correctness, and these are the one place that is fine.
- Entry ids MUST be stable: `urn:basalt:node:<node id>`, not a URL.
- A feed MUST NOT carry a presigned URL (§1.5.5) and MUST stay
  `private, no-store` (§1.5.2): a feed is a filtered view, not a publication,
  and an aggregator sharing one cache across readers would leak.
- A summary MAY quote the node's own text. Text the principal may already read
  in full is not a leak, and §9.5 redacts *resolved targets*, not an author's
  words about them.
- `robots.txt` MUST follow the audience ceiling (§12.2), not the ACL: a
  `gated` or `private` vault disallows everything, because any path a crawler
  records is one a reader had to be granted.

## 8. Linked data

| Route | Format |
|---|---|
| `/graph.jsonld` | JSON-LD 1.1 |
| `/graph.ttl` | Turtle |

- A node's IRI MUST be its gatekeeper node URL, so the graph is
  dereferenceable and following an IRI re-runs the same ACL check.
- Standard terms are used where they exist (`dcterms:title`,
  `dcterms:identifier`, `dcterms:extent`). Basalt's own terms live under
  `urn:basalt:v1:` — this spec owns no domain, and a URN cannot 404, move, or
  be taken over later.
- A redacted edge (§9.5) MUST NOT be emitted as a triple, because RDF cannot
  express "an edge exists whose target you may not know". Each node MUST
  instead carry `basalt:redactedLinks`, a count. Dropping them silently would
  publish a graph that is quietly wrong, which is what §9.5 exists to prevent.

## 9. Equivalence (normative)

These are the questions a conformance runner asks of every mounted surface.
Answers MUST agree.

| # | Question | Asked of |
|---|---|---|
| E1 | Which nodes can principal P see? | every surface that lists nodes |
| E2 | What are the bytes and metadata of node N for P? | every surface that reads a node |
| E3 | What happens for a discoverable-but-unreadable N? | all — MUST be `forbidden` |
| E4 | What happens for a nonexistent N? | all — MUST be `not_found` |
| E5 | What happens for a withheld tree path? | all — MUST be `not_found` |
| E6 | After warming the cache as P1, what does P2 see? | all — MUST be P2's own view, in either order |
| E7 | Do the operation table, the proto and the SDL list the same operations? | the descriptions themselves |
| E8 | Where two implementations could shape the same answer differently, which shape is right? | the invariants listed in the corpus |

E6 is run in both orders deliberately: a cache keyed on anything less than the
subject set serves whichever principal arrived first, and that failure is
invisible to a single-principal test suite.

E8 is the list that running two implementations side by side actually
produced: the subject set's order, which field `display_name` comes from, the
order of tag postings, whether an unresolved edge carries an explicit null
`target`, whether a node's embedded link set is a full `LinkSet`, and whether
`index_state` describes what the server did. None of them is a §8 failure —
each was one implementation shaping a reply its own way — and each would have
broken a client that switched implementations. They live in the corpus, not in
either codebase, and both implementations are held to them. Expect this list
to grow the first time a third implementation answers these questions.

## 10. Profiles and conformance

Interop surfaces are declared as **profiles**, independently of the §14.1
levels. A profile requires L4 (the gatekeeper), since every one of them is the
§12 surface in another vocabulary.

| Profile | Requires | Adds |
|---|---|---|
| `P-REST` | L4 | §2, an OpenAPI document, problem documents, conditional GET |
| `P-GRAPHQL` | L4 | §3, SDL, field-level denials, introspection |
| `P-JSONRPC` | L4 | §4.1 |
| `P-MCP` | L4 | §4.2, both transports, version negotiation |
| `P-GRPC` | L4 | §5, the proto service, code mapping |
| `P-WEBDAV` | L4 | §6, read-only class 1 |
| `P-FEEDS` | L4 | §7 |
| `P-RDF` | L4 | §8 |
| `P-INTEROP` | two or more of the above | §1 and all of §9 |

`P-INTEROP` is the one that matters. A single surface is easy; the claim worth
testing is that several of them describe the same vault.

Declare profiles in the manifest:

```yaml
publish:
  audience: gated
  interop: [P-REST, P-GRAPHQL, P-MCP, P-WEBDAV, P-INTEROP]
```

When `publish.interop` is **present** it is a ceiling, in the same shape as
the §12.2 audience ceiling: a gatekeeper MUST NOT mount a surface the vault
does not list, so an owner can take one off for every deployment of that vault
in a single edit. When it is **absent** the vault makes no claim — a vault
written before this annex says nothing about profiles — and the operator
decides what to mount.

`P-INTEROP` mounts nothing of its own; it is the claim that the surfaces
beside it agree.

## 11. Deliberately not implemented

Stated so that the gaps are choices rather than surprises.

- **Write surfaces** on every protocol (REST `PUT`, DAV class 2, MCP tools
  that mutate, GraphQL mutations). Blocked on §11 history and §8's write
  rights, not on protocol work.
- **Binary gRPC and gRPC-Web** in-process: needs HTTP/2 and a protobuf codec.
  The proto plus a Connect-aware proxy covers the same clients.
- **Subscriptions, SSE, webhooks.** A read-only gatekeeper over a store with
  no change feed has nothing to push; §10.6 digest polling is the honest
  answer until the store can say what changed.
- **SPARQL.** Serving Turtle is a few hundred lines; serving SPARQL is a query
  engine. Load `/graph.ttl` into one that exists.
- **S3-compatible read gateway.** Tempting (it would make the vault mountable
  by anything speaking S3) and refused: re-exporting the object API would
  invite clients to treat ACL-filtered keys as a bucket, and §8's inherited
  deny is exactly what a bucket cannot express.
- **ActivityPub, OAI-PMH, CalDAV, OData.** No reader asked for them; each
  would add a surface to keep equivalent for no client this format has.
