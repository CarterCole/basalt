// Runs the language-neutral ACL corpus, PROTOCOL §14.2.
//
// Each case asserts the deciding ACE, not just the boolean: two
// implementations can agree on "denied" for different reasons and only one of
// them is following §8.4.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { Principals } from '../src/acl.mjs';
import { DescriptorStore, checkAccess } from '../src/security.mjs';

const CORPUS = fileURLToPath(
  new URL('../../conformance/cases/acl/evaluation.yaml', import.meta.url));
const corpus = YAML.parse(readFileSync(CORPUS, 'utf8'));

/** Turn a case's `descriptors` map into a DescriptorStore. */
function buildStore(descriptors) {
  const folderAcls = new Map();
  const inlineAcls = new Map();
  for (const [path, desc] of Object.entries(descriptors ?? {})) {
    if (path === '/' || path.endsWith('/')) {
      const folder = path === '/' ? '' : path;
      folderAcls.set(folder, { folder: desc, entries: {} });
    } else {
      inlineAcls.set(path, desc);
    }
  }
  return new DescriptorStore({ folderAcls, inlineAcls });
}

/** Deep-merge a case's `manifest` over the corpus `defaults.manifest`. */
function mergeManifest(defaults, override) {
  const out = structuredClone(defaults ?? {});
  for (const [k, v] of Object.entries(override ?? {})) {
    out[k] = v && typeof v === 'object' && !Array.isArray(v)
      ? mergeManifest(out[k], v)
      : v;
  }
  return out;
}

function optsFor(c) {
  const m = mergeManifest(corpus.defaults?.manifest, c.manifest);
  return {
    audience: m.publish?.audience ?? 'gated',
    bypassTraverse: m.security?.bypass_traverse ?? false,
    denyUnresolved: m.security?.deny_unresolved ?? true,
  };
}

const principals = new Principals({
  users: corpus.principals.users,
  groups: corpus.principals.groups,
  roles: corpus.principals.roles,
});

for (const c of corpus.cases) {
  test(`acl: ${c.name}`, () => {
    const store = buildStore(c.descriptors);
    // A case carries either one `request` or a list of `requests`.
    const requests = c.requests ?? [{ ...c.request, expect: c.expect }];

    for (const req of requests) {
      const result = checkAccess({
        store, principals,
        principalId: req.principal,
        path: req.path,
        rights: req.rights,
        ...optsFor(c),
      });

      for (const [right, want] of Object.entries(req.expect)) {
        const got = result.decisions[right];
        assert.ok(got, `${c.name}: no decision for ${right}`);
        assert.equal(got.decision, want.decision,
          `${c.name} [${req.principal} ${right} ${req.path}]: ` +
          `decision ${got.decision} (by ${got.by}), want ${want.decision} (by ${want.by})`);
        assert.equal(got.by, want.by,
          `${c.name} [${req.principal} ${right} ${req.path}]: ` +
          `decided by ${got.by}, want ${want.by}`);
        if (want.failed_at !== undefined) {
          assert.equal(got.failed_at, want.failed_at,
            `${c.name}: failed_at ${got.failed_at}, want ${want.failed_at}`);
        }
      }
      if (c.overall !== undefined) {
        assert.equal(result.allowed, c.overall === 'allow',
          `${c.name}: overall ${result.allowed}`);
      }
    }

    // Integrity expectations (cycles, unresolved subjects).
    for (const want of c.integrity ?? []) {
      if (want.code === 'GROUP_CYCLE') {
        assert.ok(
          principals.integrity.some((i) => i.code === 'GROUP_CYCLE'),
          `${c.name}: expected a GROUP_CYCLE integrity report`);
      }
    }
  });
}
