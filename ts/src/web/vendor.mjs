// Third-party files the publish site serves under /_assets/.
//
// An allowlist, not a directory: a request name is matched against fixed
// names and never joined onto a path. Today that is one file, Mermaid's
// browser bundle, vendored in public/vendor/ (scripts/vendor-mermaid.mjs
// says why). Math needs nothing here: it is rendered to MathML on the
// server (web/markdown.mjs).

import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PUBLIC = fileURLToPath(new URL('./public/', import.meta.url));

export const MERMAID_JS = 'vendor/mermaid.min.js';

/** Absolute path of a vendored asset by its /_assets/ name, or null. */
export function vendorFile(name) {
  if (name === MERMAID_JS) return path.join(PUBLIC, 'vendor', 'mermaid.min.js');
  return null;
}

/** True when a rendered page has a diagram for site.js to draw. */
export function hasDiagrams(html) {
  return html.includes('class="language-mermaid"');
}
