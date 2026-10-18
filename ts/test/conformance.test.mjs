// Runs the language-neutral corpus for L0-L2, PROTOCOL §14.2.
//
// Expectations live in conformance/, never here: no implementation defines
// its own answers for behavior the spec covers.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import {
  validateKey, isValidKey, findCollisions, findFolderCaseDivergence,
  impliedFolders, keyToPath,
} from '../src/keys.mjs';
import { parseNote } from '../src/frontmatter.mjs';
import {
  extractLinks, buildResolver, resolveTarget, anchorResolves, extractHeadings,
} from '../src/links.mjs';

const corpus = (rel) => YAML.parse(readFileSync(
  fileURLToPath(new URL(`../../conformance/${rel}`, import.meta.url)), 'utf8'));

// ------------------------------------------------------------ L0: keys

const keys = corpus('cases/keys/validation.yaml');
for (const c of keys.cases) {
  test(`keys: ${c.name}`, () => {
    if (c.valid) {
      assert.doesNotThrow(() => validateKey(c.key), `${c.key} should be valid`);
      return;
    }
    let code = null;
    try { validateKey(c.key); } catch (e) { code = e.code; }
    assert.ok(code, `${JSON.stringify(c.key)} should have been rejected`);
    assert.equal(code, c.error, `wrong error code for ${JSON.stringify(c.key)}`);
  });
}

// ------------------------------------------------------- L1: collisions

const collisions = corpus('cases/paths/collisions.yaml');
for (const c of collisions.cases) {
  test(`collisions: ${c.name}`, () => {
    const groups = findCollisions(c.keys);
    if (!c.collides) {
      assert.equal(groups.length, 0,
        `${c.keys.join(' vs ')} should not collide`);
      return;
    }
    assert.equal(groups.length, 1, 'expected exactly one colliding group');
    // §2.2: the surviving key is deterministic, so a repair is reproducible.
    assert.equal(groups[0][0], c.survivor);
  });
}

for (const c of collisions.cases.filter((x) => x.folder_divergence)) {
  test(`collisions: ${c.name} reports folder divergence`, () => {
    const groups = findFolderCaseDivergence(c.keys);
    assert.equal(groups.length, 1, 'expected one diverging folder group');
    assert.deepEqual(groups[0], c.folder_divergence);
  });
}

const folders = corpus('cases/paths/folders.yaml');
for (const c of folders.cases) {
  test(`folders: ${c.name}`, () => {
    const paths = c.keys.map(keyToPath).filter(Boolean);
    assert.deepEqual(impliedFolders(paths), c.folders);
  });
}

// ------------------------------------------------------ L1: frontmatter

const fm = corpus('cases/frontmatter/parsing.yaml');
for (const c of fm.cases) {
  test(`frontmatter: ${c.name}`, () => {
    // No path means the case is not exercising the filename-stem title
    // fallback, so pass '' rather than inventing a name for it to fall back to.
    const got = parseNote(c.content, c.path ?? '');
    const want = c.expect;

    // §5.2: frontmatter `tags` merge with inline #tags from the body, which
    // is a property of the pair, so the runner merges them exactly as the
    // indexer does.
    const mergedTags = [...new Set([...got.tags, ...extractLinks(got.body).tags])];

    if ('id' in want) assert.equal(got.id, want.id, 'id');
    if ('title' in want) assert.equal(got.title, want.title, 'title');
    if ('tags' in want) assert.deepEqual(mergedTags, want.tags, 'tags');
    if ('aliases' in want) assert.deepEqual(got.aliases, want.aliases, 'aliases');
    if ('publish' in want) assert.equal(got.publish, want.publish, 'publish');
    if ('body_starts_line' in want) {
      assert.equal(got.bodyStartLine, want.body_starts_line, 'bodyStartLine');
    }
    if (want.errors) {
      assert.deepEqual(
        got.errors.map((e) => ({ severity: e.severity, code: e.code })),
        want.errors, 'errors');
    }
  });
}

// --------------------------------------------------- L2: link extraction

const extraction = corpus('cases/links/extraction.yaml');
for (const c of extraction.cases) {
  test(`extraction: ${c.name}`, () => {
    const parsed = parseNote(c.content, c.path ?? 'Notes/Source.md');
    const got = extractLinks(parsed.body);

    if (c.edges) {
      assert.equal(got.edges.length, c.edges.length,
        `edge count: got ${JSON.stringify(got.edges.map((e) => e.raw))}`);
      for (const [i, want] of c.edges.entries()) {
        const g = got.edges[i];
        assert.equal(g.kind, want.kind, `edge ${i} kind`);
        assert.equal(g.raw, want.raw, `edge ${i} raw`);
        assert.equal(g.alias, want.alias, `edge ${i} alias`);
        assert.equal(g.anchor, want.anchor, `edge ${i} anchor`);
        if (want.line !== undefined) assert.equal(g.line, want.line, `edge ${i} line`);
      }
    }
    if (c.tags) {
      const all = [...new Set([...parsed.tags, ...got.tags])];
      assert.deepEqual(all, c.tags, 'tags');
    }
  });
}

// -------------------------------------------------- L2: link resolution

const res = corpus('cases/links/resolution.yaml');
const resolver = buildResolver(res.vault.nodes.map((n) => ({
  id: n.id, path: n.path, aliases: n.aliases ?? [],
})));

for (const c of res.cases) {
  test(`resolution: ${c.name}`, () => {
    const got = resolveTarget(resolver, c.from, stripAnchor(c.target));
    assert.equal(got.node?.id ?? null, c.resolves_to, 'resolved node');
    assert.equal(got.by, c.by, 'resolution step');
    if (c.ambiguous !== undefined) {
      assert.equal(got.ambiguous, c.ambiguous, 'ambiguity flag');
    }
    if (c.candidates) {
      assert.deepEqual(got.candidates, c.candidates, 'candidate order');
    }
    if (c.anchor_resolved !== undefined) {
      // §9.3: a bad fragment never makes the edge unresolved; only the
      // anchor fails. The fixture vault has no heading data, so an anchor
      // that names anything cannot resolve.
      const anchor = c.target.includes('#') ? c.target.split('#')[1] : null;
      assert.equal(anchorResolves(anchor, [], []), c.anchor_resolved);
    }
  });
}

function stripAnchor(target) {
  const i = target.indexOf('#');
  return i === -1 ? target : target.slice(0, i);
}
