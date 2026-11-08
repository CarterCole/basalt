# Proposal: paste or drop an image into a note on the publish site

| | |
|---|---|
| **Status** | Proposed. Nothing is implemented. Implementation waits on Carter's answers to §14. |
| **Date** | 2026-11-08 |
| **Changes** | PROTOCOL §12.7 item 8 (amended), a new PROTOCOL §12.8, INTEROP §1.5 rule 1 and §11 (one sentence each) |
| **Builds on** | `storeObject` / `basalt_store` (d8a6244) and the site CSP as of def0819. Both commits are on `fix-search-index-prototype-words`, not yet on `main`, so the files named below are read from there. |

## 1. Context

On GitHub, pasting a screenshot into a comment box uploads it and inserts
`![image](https://…)` at the cursor. Basalt has no equivalent. The publish
site has no editor, and the site has no write path at all.

What exists today:

- **The site** is rendered per principal by `ts/src/web/site.mjs` and
  `pages.mjs`, with `public/site.js` as progressive enhancement. The router
  answers every request other than GET and HEAD on a site path with 405
  (`ts/src/serve/router.mjs`, the `if (this.site)` block).
- **Writes** go through `storeObject` (`ts/src/store.mjs`), which implements
  §12.7. It only creates, never overwrites. It needs `create_child`, and
  `write_acl` for a note that carries an inline ACL. It reloads ACLs on every
  call and mints the id when the object is stored (frontmatter for a note, an
  entry sidecar for anything else). It stamps `created_by`. It checks UTF-8,
  withheld trees and size (`MAX_STORE_BYTES`, 25 MiB), then reindexes. There
  are two callers:
  - `basalt add` (`ts/bin/basalt.mjs`), run by the operator or with `--principal`;
  - `basalt_store` (`ts/src/serve/write.mjs`), on stdio MCP only, behind
    `--writable --principal`.
- **The stance.** §12.7 item 8 says a write SHOULD be offered only to a
  process the operator started and bound to one principal (stdio). It adds
  that an HTTP endpoint "needs an answer to a cross-site request … and none
  is specified". The header of `write.mjs` and INTEROP §1.5 and §11 all say
  the same: stdio, "and nowhere else".
- **Identity over HTTP** is `Gatekeeper({ identify })`. `basalt serve` passes
  `identify: () => forced ?? 'anonymous'`, so `--principal` makes *every*
  request that principal. There is no login, cookie or session.

The last point is why item 8 is right as written. Add a write endpoint to
today's `basalt serve --principal u:carter`, and any web page Carter's
browser visits could POST to `127.0.0.1:4380` and be judged as `u:carter`.
The identity belongs to the port, not to whoever is calling.

## 2. Decision in brief

1. **Change the spec, don't route around it.** Amend §12.7 item 8 and add
   §12.8, which gives the cross-site answer that item 8 says is missing
   (§3).
2. **v1 writes new notes only.** Editing an existing note means replacing
   it, and §12.7 leaves replacement to §11 history on purpose (§4).
3. **Identity comes from a session, not the port.**
   `basalt serve --writable --principal u:carter` prints a login link once
   per process. Opening it sets an HttpOnly, `SameSite=Strict` session
   cookie. A request without that cookie is `anonymous`, and `anonymous`
   never writes (§5).
4. **Four checks against cross-site requests:**
   - an exact `Origin` match against origins the operator configured, never
     ones derived from `Host`;
   - `Sec-Fetch-Site: same-origin`;
   - a session-bound token in a custom header;
   - no CORS on the write route.

   All four are decided from the headers, before the body is read (§6).
5. **Images stay in the browser until Save.** Then the note and its
   attachments go up in one request and are stored by one call. That call
   loads once, validates everything before writing anything, and reindexes
   once. A draft that is never saved leaves nothing in the vault. That
   matters because nothing can delete (§7).
6. **Attachments go in the note's own folder by default,** named the way
   Obsidian names them. The server refuses a save if an attachment would be
   readable by anyone who cannot read the note (§8).
7. **Only raster images and PDF.** No SVG over HTTP (§7.4).
8. **The editor page gets its own CSP.** It adds `img-src blob:` and
   `frame-ancestors 'none'`. Every other page keeps the current policy
   (§10).
9. **A static export has no server, so it has no editor.** The export
   contains nothing from the editor, and a test checks that (§11).

## 3. §12.7, head-on

**Could it fit without changing the spec?** Technically, yes. The HTTP
sentence in item 8 is a SHOULD followed by a remark, not a MUST NOT. An
implementation could add an HTTP endpoint and still claim conformance. But
item 8 names the exact gap ("none is specified"). The TypeScript
implementation is the reference, so whatever it ships becomes the de facto
spec for `rust/` and `python/`. The honest move is to write the answer down.

**What stays the same.** Items 1–7 are unchanged. Writing stays optional and
outside every conformance level (§14.1), and it stays create-only.

**What changes.** Item 8 gets a second permitted caller: a browser session
bound to one principal the operator named, under §12.8.

**Why this keeps the point of item 8.** The real requirement in item 8 is
that the caller belongs to the operator and is bound to one principal for
its lifetime. Stdio gets that from the pipe. §12.8 gets it from a secret
that only the operator's terminal has seen, traded for a cookie that only
same-origin requests can use. The operator still starts the process, the
principal is still fixed at startup, and nothing is on unless the operator
asks.

Proposed text, replacing item 8:

> 8. **Be off unless asked, and bound to the operator.** The write MUST be an
>    explicit operator choice and MUST be evaluated as a principal the
>    operator named, never `anonymous`. It SHOULD be offered only where the
>    caller is a process the operator started and bound to one principal for
>    its lifetime (stdio), or over HTTP under §12.8. A gatekeeper that reduces
>    every request to the same principal whoever sent it MUST NOT accept
>    writes: any page a browser visits can send a request to a loopback
>    address.

And a new section:

> ### 12.8 Creating objects over HTTP (optional)
>
> A gatekeeper MAY accept §12.7 writes from a browser. Every item of §12.7
> applies, and in addition:
>
> 1. **Identity from a credential, not a port.** The principal MUST come from
>    a credential the gatekeeper issued or verified for this caller (§12.1):
>    a session established with a secret the operator handed out, or an
>    authenticating proxy the operator configured the gatekeeper to trust.
> 2. **Same origin only.** A write MUST be refused unless `Origin` is present
>    and equal to one of the origins the operator configured. That set MUST
>    NOT be derived from the request (`Host`, `X-Forwarded-*`), which a
>    DNS-rebinding page controls. When `Sec-Fetch-Site` is present it MUST be
>    `same-origin`. The write MUST require a request header that a
>    cross-origin page cannot send without a CORS preflight, and the write
>    route MUST NOT answer CORS, whatever the gatekeeper does for reads.
> 3. **Decided before the body.** Items 1 and 2 MUST be decided from the
>    headers before the body is read, and the body MUST be bounded before it
>    is buffered.
> 4. **No attachment more visible than its note.** When one request stores a
>    note and objects that note embeds, the request MUST be refused if any
>    principal a request can reduce to (§12.1) could read one of those
>    objects but not the note. A screenshot pasted into a private note must
>    not become public because of the folder it was filed in.
> 5. **No active content.** An implementation SHOULD refuse objects that a
>    browser executes when they are served from the vault's own origin (SVG,
>    HTML, XML). A static export (§12.6) serves them without the
>    gatekeeper's headers.
> 6. **Not an interop surface.** This write belongs to the publish site. It
>    MUST NOT be offered or advertised as an operation of any INTEROP
>    profile.

INTEROP §1.5 rule 1 and §11 each gain one clause: "… and the publish site's
editor under PROTOCOL §12.8". The header comment in `write.mjs` and the
discovery note "All surfaces are read-only" are updated to match.

## 4. Scope: new notes only

GitHub offers paste in two places. One is a comment box, where everything is
new text. The other is the file editor, which changes a file that already
exists.

Basalt's create-only write covers the first case. A new note and the images
in it are all new objects.

The second case is a replacement. §12.7 item 1 refuses it and says why:
replacing destroys work, and §11 history is what makes that recoverable.
INTEROP §11 says the same. An endpoint that replaces a note would need:

- `write` on the note (§8.1);
- `If-Match` on the etag the editor loaded, so a lost race is a conflict and
  is not retried blindly (§11.3);
- the existing `basalt:` block kept as it is: the id and `created_by` stay,
  and a change to `basalt.acl` needs `write_acl`;
- a version record (§11), or the store's `versioning` capability, so the
  previous text survives.

That is a proposal of its own. Everything in this one carries over to it
unchanged: the session, the cross-site checks, the request shape, the
attachment tray, attachment naming and the visibility rule.

## 5. How a browser request gets a principal

**Today**, `identify(req)` returns the forced `--principal`, or `anonymous`.

**Proposed** for `basalt serve --writable --principal u:carter`:

- **Startup.** The server generates a 256-bit login secret and prints it to
  the terminal as `http://127.0.0.1:4380/_login?token=…`. The secret is never
  written to disk or to a log.
- **`GET /_login?token=…`.** The server compares the token in constant time.
  On a match it mints a random 256-bit session id and keeps it in memory,
  mapped to the principal. It responds with
  `Set-Cookie: basalt_session=<id>; HttpOnly; SameSite=Strict; Path=/`
  (adding `Secure` when the configured origin is https) and a 303 to `/`, so
  the token does not stay in the address bar. The response sends
  `Referrer-Policy: no-referrer`.
  - Login CSRF (planting the attacker's own session in the victim's browser)
    gets an attacker nothing. There is one principal, and the attacker does
    not have the secret.
- **`identify(req)` in writable mode** maps the session cookie to its
  principal, and anything else to `anonymous`. This is the reduction §12.1
  asks for. The client never sends a principal id. It presents a credential
  the gatekeeper issued, and the gatekeeper does the mapping.
- **`--principal` changes meaning under `--writable`.** It no longer means
  "every request is this principal". It means "the login link signs in as
  this principal". Reads without the cookie are anonymous, so the operator
  logs in once. A forced identity and writes cannot be combined.
- **Lifetime.** The secret can be reused for the life of the process
  (Jupyter's model), so a second browser can log in too. A restart rotates
  it and ends every session. v1 has no expiry within a process.
- **Listening address.** v1 listens on loopback only. `--writable` refuses a
  non-loopback host unless `--public-url` is https, because a session cookie
  sent over plain HTTP on a LAN can be sniffed.
- **`created_by`.** The principal is the session's. `agent` and `account`
  come from `--agent` / `--account` on `serve`, exactly as on `mcp`.
  `client` is `{ name: basalt-site, version }`. The User-Agent is not
  recorded.

**Hosted (phase 2, not designed in detail here).** §12.1 already lists
"a reverse proxy header" as a way to identify a request. Behind an
authenticating proxy (oauth2-proxy, Cloudflare Access, `tailscale serve`),
`identify` would:

- read one configured header, and only when the gatekeeper listens on
  loopback or a unix socket behind that proxy;
- map the header's value to a principal id through a table the operator
  supplies.

The cross-site checks are the same, and they matter more there: the proxy's
own cookie goes along on cross-site requests under whatever `SameSite` the
proxy chose. The token would be an HMAC over the principal and a time window
instead of a Basalt session.

## 6. Cross-site requests

**Who can attack, and what stops each one:**

- **Any web page** (`evil.example`) can POST to `127.0.0.1:4380/_store` with
  a form or with `fetch` in `no-cors` mode.
  - The cookie is not sent, because the request is cross-site and the cookie
    is `SameSite=Strict`, so the request is `anonymous` and gets a 401.
  - `Origin` does not match.
  - A custom header forces a preflight, and the preflight fails.
- **A page on another loopback port** (`127.0.0.1:3000`, for example a dev
  server running third-party code). This one is same-site: `SameSite` ignores
  ports, and so do cookies, so **the cookie is sent**.
  - `Origin` is `http://127.0.0.1:3000`, which is not a configured origin.
  - The custom header forces a preflight, and the route never answers CORS.
- **DNS rebinding** (`evil.example` re-resolves to 127.0.0.1). The page is
  same-origin with itself and can read the responses.
  - `Origin` and `Host` are `evil.example:4380`, which is not configured.
    This is why the expected origin must not come from `Host`:
    `Router.#base()` derives it from `Host` / `X-Forwarded-*`, and that
    function MUST NOT be used here.
  - The cookie is host-only for `127.0.0.1`, so it is not sent.
- **Framing the editor to clickjack Save**, from another loopback port.
  - `frame-ancestors 'none'` and `X-Frame-Options: DENY` on the editor.
- **A local process or a browser extension** can already read the vault
  directly. This is out of scope, as it is for stdio.

**The layers, and what each one is for:**

1. **The `Origin` allowlist.** `http://127.0.0.1:<port>`,
   `http://localhost:<port>`, `http://[::1]:<port>`, plus the origin of
   `--public-url`, fixed at startup. A missing `Origin` is refused, because
   every current browser sends it on POST. This is the layer doing the work:
   it is the only one that stops the other-port case.
2. **`Sec-Fetch-Site`, when present, must be `same-origin`.** The browser
   checks the same thing independently, at no cost.
3. **The `X-Basalt-Token` header.** Its value is
   `base64url(HMAC-SHA256(process key, session id))`, rendered into the
   editor page as `<meta name="basalt-token">`. Requiring a custom header
   forces a CORS preflight for any cross-origin sender. Binding it to the
   session means a bug in one layer (an `Origin` parser bug, a proxy that
   rewrites `Origin`) is not enough for a write CSRF.
4. **The `SameSite=Strict`, HttpOnly cookie.** It keeps a cross-site request
   from being authenticated at all. It does nothing for other ports on
   loopback, which is why layers 1–3 exist.

The routes `/_login`, `/_new` and `/_store` never carry
`Access-Control-Allow-*`. The router's `--cors` OPTIONS shortcut must exclude
them. Chrome's Private Network Access blocks some requests from public sites
to loopback, but the design does not rely on it.

## 7. The store request

### 7.1 Shape

`POST /_store`, `multipart/form-data`, with these parts:

- `meta`: JSON, `{ note: { path, title? }, attachments: [{ part, path, alt? }] }`
- `text`: the note's markdown
- one binary part per attachment, named by `part`

The response is `201` with `Location: <note href>` and
`{ note: { path, id, href }, attachments: [{ path, id }], created_by }`.

Errors use the site's `problem+json`:

- `400 bad_request`
- `401` (no session)
- `403` / `404` on the folder, by §12.3's rule
- `409 conflict`, with `paths: [...]`
- `413 too_large`
- `422 visibility` (§8)

Node's built-in `Request.formData()` (undici) parses the body, so there is
no new dependency. That was checked on Node 25; confirm it on Node 20, the
`engines` floor, before relying on it.

### 7.2 Order of checks

The router reads the body of every POST at the top of `handle()`, before
routing. `/_store` has to be matched before that read.

1. The site is writable. Otherwise 405, as today.
2. `Origin` and `Sec-Fetch-Site` (§6). Otherwise a generic 403 that names
   nothing in the vault.
3. A valid session gives the principal. Otherwise 401.
4. `X-Basalt-Token` matches, compared in constant time. Otherwise 403.
5. `Content-Length` is present and within the request cap (§7.4). Otherwise
   411 or 413.
6. Read the body with a byte counter that aborts at the cap, then parse it.
7. Check each part: size within `MAX_STORE_BYTES`, extension on the
   allowlist, and magic bytes that agree with the extension (§7.4).
8. `storeNoteWithAttachments`, in the per-vault serialized chain:
   - `vault.load()`;
   - validate every object;
   - write the attachments, each one content first and then its sidecar
     entry;
   - write the note last;
   - reindex once.
9. `surface.invalidate()`, then 201.

The note is written last so that the object a reader sees, the note, only
appears once everything it embeds is already there.

### 7.3 `create_child`, through `storeObject`'s own code

`store.mjs` gains `storeNoteWithAttachments(vault, { principal, note,
attachments, provenance })`. Its validation step is the body of
`storeObject` factored out, so `basalt add` and `basalt_store` keep their
current behaviour. For every object it runs:

- `checkPath`, which covers key validity, withheld trees and names the
  filesystem transport skips;
- kind detection and the strict UTF-8 check;
- the §2.2 collision checks, which now also cover the request's own paths
  colliding with one another;
- `authorize(vault, principal, folder, ['create_child'])` for each distinct
  folder, plus `['write_acl']` when the note's frontmatter sets
  `basalt.acl`. The 404/403 split applies to the folder.

On top of those it adds:

- **Each attachment must be embedded by the note.** `extractLinks` and
  `resolveTarget` (`links.mjs`) must find an embed that resolves to the
  attachment's path. This
  makes the endpoint "a note and the files it shows", not a general
  uploader.
- **The visibility rule** (§8).

The principal always comes from the session and is never a form field.
Because `vault.load()` runs on every save, revoking `create_child` in
`acl.yaml`, or suspending the user in `users.yaml`, takes effect on the next
save without a restart. The editor's folder picker is computed from the same
check for convenience only; the server does not trust it.

If another process creates one of the paths between validation and the
write, the conditional put fails. The response is then a 409 that also lists
`stored: [...]`. The client drops those attachments from its retry: they
exist, they are bound, and the text already points at them.

### 7.4 Limits and types

**Per object:** `MAX_STORE_BYTES` (25 MiB), unchanged. It is enforced by the
store and checked earlier for each part. The editor also refuses a larger
file the moment it is pasted.

**Per request:** at most 64 MiB and 20 attachments, overridable with
`--max-upload`. The 1 MiB `MAX_BODY` stays as it is for every other POST.
Only one `/_store` body is buffered at a time; a second request arriving
meanwhile gets `429` with `Retry-After`.

**Types:** `.png .jpg .jpeg .gif .webp .avif .pdf`. The extension decides the
kind and the media type (§5.1). The magic-number check (`\x89PNG`,
`FF D8 FF`, `GIF8`, `RIFF…WEBP`, `ftypavif`/`ftypavis`, `%PDF-`) only
*refuses* a mismatch. It never reclassifies, so kind still comes from the key
alone.

**SVG is refused** over HTTP. An SVG opened directly runs its scripts. The
gatekeeper's CSP would stop that, but a GitHub Pages export sends no CSP.
`basalt add` can still store SVG, as the operator's choice.

## 8. Where pasted images land, and the link

**Default: the note's own folder.** Names follow Obsidian's convention,
`Pasted image 20261108093012.png`, generated in the browser from the local
clock. A second image within the same second gets ` 2`, ` 3`. A dropped file
keeps its own name (normalised to NFC). The link inserted at the cursor uses
the path form,
`![[Notes/Ideas/Pasted image 20261108093012.png]]`, which is what
`storeThrough` already returns: it stays unambiguous when the same filename
exists elsewhere (§9.3), and Obsidian resolves it too. Identity is in
`meta/folders/<folder>/entries.yaml` through `addSidecarEntry`, with `id`,
`alt` and `created_by`.

**Why not `Assets/`,** even though `basalt add` defaults to it:

- In the `minimal` conformance vault, `Assets/` grants `read` to `everyone`
  by design. Its `acl.yaml` comment says an embedded image must be readable
  by anyone who can read the note that embeds it. That holds for images an
  author files on purpose. A screenshot pasted into a note in a restricted
  folder would instead become readable by everyone.
- In a vault like `demo`, whose root grants `publish`, the screenshot would
  also go out in the next static export, while the note it belongs to would
  not.
- A sibling of the note inherits exactly what the note inherits. One
  `create_child` decision then covers both objects.

**The rule is a check; the default is chosen so the check passes.** For
every principal a request can reduce to, the server refuses the save if the
principal can read an attachment but cannot read the note. Those principals
are:

- `anonymous`, for which `vault.can` already requires `publish`, as the
  exporter relies on;
- every user in `principals/users.yaml`;
- one id the vault does not list, which matches only `everyone`, since §7.3's
  `authenticated` requires a real user.

That is a few hundred `can()` calls on a personal vault.

The check does not cover a note whose frontmatter sets `basalt.acl`, because
`can()` cannot see an inline descriptor before the note is indexed. In v1
such a note may be saved, but not with attachments.

**Other cases:**

- **A note in the vault root** cannot have siblings that are not notes
  (§12.7 item 4). Its attachments go to `Assets/`, still subject to the
  check.
- **An operator who wants a fixed folder** passes `--attachments Assets/`,
  and the check still applies.

**Rendering needs one fix.** For an untitled asset the indexer falls back to
the filename stem as the title, and `renderEmbed` shows a `<figcaption>`
whenever there is a title. Every pasted image would therefore be captioned
"Pasted image 20261108093012". The site's sidecar `alt` is also never used:
`imgTag` takes the link alias, else the title. The renderer should:

- take `alt` from the link alias, else the sidecar `alt`, else the sidecar
  `title`, else empty;
- show a caption only for an explicit sidecar `title`.

It can read these from `vault.sidecars`, so `nodes.json` and the corpus are
untouched. This fix also helps assets that `basalt add` stores today.

## 9. The minimal editor

**Way in.** A "New note" link (`/_new?in=<folder>`) on the home page, on
folder pages and on note pages (where it points to the note's folder). It is
rendered only when all three hold:

- the site is writable;
- the request has a session;
- the principal has `create_child` on that folder.

**`/_new`** without a session is a 401 page that says to open the link
printed by `basalt serve`. With one, it shows a single form:

- **Folder:** a `<select>` of the folders where the principal has
  `create_child`, preselected from `?in=`.
- **Title:** a text field that sets the filename. A live line underneath
  reads "Saved as Notes/Ideas/My idea.md".
- **Body:** a monospace `<textarea>` with autofocus. The hint reads "Paste or
  drop images; they upload when you save."
- **Attachments tray** under the textarea. Each pending file shows a
  thumbnail (a `blob:` URL) or a PDF mark, its name and size, an alt-text
  field and a remove button.
  - Removing a file from the tray also removes its exact link text.
  - Deleting the link text by hand greys the file out as "not used", and it
    is not uploaded.
- **Attach files…:** a file input limited to the allowed types, for keyboard
  and mobile users who cannot paste or drag.
- **Save** (Ctrl/Cmd+Enter) and **Cancel.** An `aria-live` status line
  reports progress and errors.

**`public/editor.js`** is a new file, loaded only by `/_new`, so `site.js`
stays editor-free:

- **`paste`:** if `clipboardData.files` holds an allowed type, the default
  paste is prevented, the file is named, `![[…]]` is inserted at the
  selection with `setRangeText`, and the file joins the tray. Plain text
  pastes through untouched.
- **`dragover` / `drop` on the textarea:** the same, inserting at the
  current selection.
- **Save:** the files still referenced are sent with `XMLHttpRequest`
  (which reports upload progress, where `fetch` does not), carrying the
  `X-Basalt-Token` header.
  - On 201 the page navigates to the new note.
  - On a 409 that names attachment paths, those files are renumbered, the
    text is updated and the save is retried once.
  - Any other error is shown in the status line, and the draft is kept.
- **Leaving the page:** `beforeunload` warns while there is text or a pending
  file. The text is also kept in `localStorage` per folder, as a convenience
  for the viewer. Images are not kept, and the tray says so.
- **v1 has no rendered preview** (open question 8).

## 10. Content-Security-Policy

Today's site policy (`router.mjs`, as of def0819) is:

```
default-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self';
connect-src 'self'; object-src 'self'; base-uri 'none'; form-action 'self'
```

**Every page except the editor keeps it unchanged.** The router sets the
CSP for each response; the site would return an override for `/_new` only:

```
default-src 'none'; img-src 'self' data: blob:; style-src 'self'; script-src 'self';
connect-src 'self'; object-src 'self'; base-uri 'none'; form-action 'self';
frame-ancestors 'none'
```

- `blob:` lets pending pastes show before they are saved. A `blob:` URL can
  only be minted by the page itself, and this source is scoped to the one
  page that needs it.
- `frame-ancestors 'none'` (plus `X-Frame-Options: DENY` for older
  browsers) stops a page on another loopback port from framing the editor.
  `default-src` does not cover framing, so it has to be stated.
- `script-src 'self'` stays. The token reaches `editor.js` through a
  `<meta>` tag, not an inline script.
- `connect-src 'self'` already admits the XHR to `/_store`.
- The editor page and `/_login` are `Cache-Control: no-store`. The router's
  default is already `private, no-store`, and the editor page carries the
  token.

Separately, the rest of the site could take `frame-ancestors 'self'`. It
would be `'self'` rather than `'none'` because def0819's PDF `<object>`
embeds the site's own `/_raw/` URLs. That is a one-line hardening, not part
of this feature.

## 11. Static export

An exported site has no server. §12.8 needs a gatekeeper, so the export
cannot accept writes, and it should not pretend it can:

- `exportSite` builds a `Site` with no write configuration and renders as
  `anonymous`. Every editor affordance needs a writable `Site` and a session
  principal with `create_child`, so none is rendered.
- `editor.js` is a separate file. The exporter's explicit copy list
  (`site.css`, `site.js`, and Mermaid when a page needs it) does not include
  it.
- `/_new`, `/_store` and `/_login` do not exist in the output.
- `editor.js` also does nothing when it sees `basalt-static`, as a second
  guard.
- **Test:** export a vault and assert that the output contains no `/_new`,
  no `basalt-token` and no `editor.js`.

For a static site, the way to add images stays as it is today:

1. Write locally, with `basalt serve --writable`, Obsidian or `basalt add`.
2. Re-export, or push and let the Pages workflow republish.

The visibility rule pays off here. A private note's pasted screenshot sits
in the private folder, and the export filter drops it together with the
note.

## 12. Alternatives considered

1. **Upload at paste time,** as GitHub does. Rejected. With create-only
   writes and no delete, every abandoned draft would leave permanent orphan
   objects. Each paste would also mean a full reload and reindex, and N
   separate requests to authorize. Its advantages, a real preview at once
   and names chosen by the server, are cheap to get another way: a `blob:`
   preview, and client-side naming with a 409 retry.
2. **`POST /api/v1/store`, or a write operation in `ops.mjs`.** Rejected.
   `ops.mjs` is projected into five surfaces at once, and `write.mjs` keeps
   writes out of it on purpose. The cross-site answer also belongs to the
   browser surface. Callers that are not browsers already have `basalt add`
   and stdio MCP.
3. **A fixed `Assets/` folder as the default.** Rejected, for the reasons in
   §8. It stays available as an option, guarded by the same check.
4. **Keep the forced `--principal` and add only an `Origin` check.**
   Rejected. Then a single bug in one header check is a full write CSRF. With
   a session, a request without the cookie is `anonymous` from the start, so
   `Origin` is the second line of defence, not the only one.
5. **A fallback form for browsers without JavaScript.** Rejected for v1.
   Paste and drop need JavaScript anyway. A native form post would have to
   carry the token in the body, so the body would be read before the token
   is checked. One request shape is easier to defend.
6. **The server rewrites link text when a name collides.** Rejected. A note
   is stored exactly as typed, apart from the minted `basalt:` block (§12.7
   items 4–5).
7. **"Edit on GitHub" links from a static site whose vault is in git.**
   Rejected. GitHub's paste uploads to its own attachment CDN and inserts an
   https URL. The image never enters the vault, has no id and no ACL, and is
   public to anyone who has the URL, whatever the note's ACL says.
8. **Editing existing notes now.** Deferred to its own proposal (§4).

## 13. Implementation plan (after approval)

Only `ts/`; there are no corpus write cases, so `rust/` and `python/` are not
held to it.

| File | Change |
|---|---|
| `protocol/PROTOCOL.md` | §12.7 item 8 amended and §12.8 added (§3 above) |
| `protocol/INTEROP.md` | one clause each in §1.5 rule 1 and §11 |
| `ts/src/store.mjs` | factor validation out of `storeObject`; add `storeNoteWithAttachments` (embed check, visibility rule, one reindex) |
| `ts/src/serve/write.mjs` | a surface-level wrapper that invalidates the cache; header comment updated |
| `ts/src/web/session.mjs` (new) | login secret, sessions, cookie parsing, token HMAC, the `Origin` / `Sec-Fetch-Site` checks |
| `ts/src/serve/router.mjs` | `/_login` and `/_store` matched before the body is read; `identify` from the session in writable mode; editor CSP; `--cors` excluded from the write routes |
| `ts/src/web/site.mjs`, `pages.mjs` | `/_new`, the "New note" affordance, `editorPage` |
| `ts/src/web/markdown.mjs` | alt and figcaption from the sidecar (§8) |
| `ts/src/web/public/editor.js` (new), `site.css` | the editor |
| `ts/bin/basalt.mjs` | `serve --writable` with `--principal`, `--agent`, `--account`, `--attachments`, `--max-upload`; refuses a non-loopback host without https |
| `README.md` | a short section next to the `basalt_store` one |

Tests:

- **Cross-site cases:** no `Origin`, a foreign `Origin`, another loopback
  port, a rebinding `Host`, no token, a wrong token, a token from another
  session, no cookie, `--cors` set, and a cross-site `Sec-Fetch-Site`.
- **Limits:** an oversized `Content-Length` is refused before any byte of
  the body is read.
- **Authorization:** `create_child` denied with `list` (403) and without it
  (404), and revocation taking effect without a restart.
- **The visibility rule:** an attachment in `Assets/` of the minimal vault
  next to a restricted note is refused.
- **Requests:** an attachment the note does not embed, SVG, a magic-number
  mismatch, a 409 followed by retry with `stored`, and the order of writes.
- **The static export** contains nothing from the editor.

## 14. Open questions for Carter

1. **Is a new note with pasted images enough for v1,** or is editing an
   existing note the real need? If it is editing, the replace proposal (§4)
   comes first, and it depends on §11 history or on the store's
   `versioning`.
2. **Where should attachments go?** The recommendation is the note's own
   folder. The alternatives are a fixed `Assets/`, a subfolder per folder
   (`attachments/`), or Obsidian's own `attachmentFolderPath` when the vault
   has `.obsidian/app.json`. Is Obsidian's `Pasted image <timestamp>` naming
   right?
3. **Should this change the spec** (§12.7 item 8, the new §12.8, and the
   INTEROP clauses)? The alternative is to keep it as an extension of the
   TypeScript implementation only, documented in the README.
4. **Should the login secret be reusable** for the life of the process (the
   recommendation), single-use, or time-limited?
5. **Is hosted mode,** behind an authenticating proxy, ever wanted, or does
   writing stay local only?
6. **Should `--principal` change meaning under `--writable`,** or should
   there be a new flag (for example `--login u:carter`) so that `--principal`
   always means "force this identity"?
7. **Should the editor strip EXIF / GPS from dropped JPEGs** by re-encoding
   them in a canvas? That costs fidelity. Screenshots pasted from the
   clipboard carry no location.
8. **Is a rendered Preview tab wanted in v1?** It would be a
   `POST /_preview` behind the same checks, with pending images swapped for
   their `blob:` URLs.
9. **Are the limits right:** 64 MiB and 20 attachments per request, 25 MiB
   per object? And is refusing SVG over HTTP acceptable?
10. **Should the alt and figcaption fix (§8) ship on its own first?** It
    already affects assets stored with `basalt add`.
