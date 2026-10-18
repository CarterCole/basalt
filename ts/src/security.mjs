// Descriptor lookup and the full access check, PROTOCOL §8.5 and §8.6.
//
// evaluateChain() in acl.mjs decides one object against one chain. This module
// builds those chains from the vault's ACL files and composes the traverse
// checks, which are separate evaluations rather than one flattened pass.

import { ancestorFolders, parentFolder, basename, isFolder } from './keys.mjs';
import { evaluateChain, subjectSet, RIGHTS } from './acl.mjs';

/**
 * A descriptor store backed by per-folder ACL files (§8.6).
 *
 * `folderAcls` maps a folder path ("", "Notes/") to the parsed acl.yaml:
 *   {folder: {owner, protected, dacl}, entries: {"Name.md": {...}}}
 * `inlineAcls` maps a node path to a descriptor from its frontmatter, which
 * replaces rather than merges with the folder file's entry.
 */
export class DescriptorStore {
  constructor({ folderAcls = new Map(), inlineAcls = new Map() } = {}) {
    this.folderAcls = folderAcls;
    this.inlineAcls = inlineAcls;
  }

  /** The descriptor for a folder path, or null. */
  forFolder(folderPath) {
    return this.folderAcls.get(folderPath)?.folder ?? null;
  }

  /** The descriptor for a node path, inline winning over the folder file. */
  forNode(nodePath) {
    if (this.inlineAcls.has(nodePath)) return this.inlineAcls.get(nodePath);
    const folder = parentFolder(nodePath);
    return this.folderAcls.get(folder)?.entries?.[basename(nodePath)] ?? null;
  }

  /** The descriptor for any path, folder or node. */
  forPath(path) {
    return isFolder(path) ? this.forFolder(path) : this.forNode(path);
  }

  /**
   * The chain for a path (§8.4 step 2): the object's own descriptor, then each
   * ancestor folder's, nearest first, truncated at the first `protected`.
   */
  chainFor(path) {
    const chain = [];
    const own = this.forPath(path);
    chain.push({ path, descriptor: own ?? {}, distance: 0 });
    if (own?.protected) return chain;

    // ancestorFolders returns root-first; walk it backwards for nearest-first.
    const ancestors = isFolder(path)
      ? ancestorFolders(path.replace(/\/$/, '') + '/x').slice(0, -1)
      : ancestorFolders(path);

    let distance = 1;
    for (let i = ancestors.length - 1; i >= 0; i--) {
      const folder = ancestors[i];
      if (folder === path) continue;
      const d = this.forFolder(folder);
      chain.push({ path: folder, descriptor: d ?? {}, distance });
      distance++;
      if (d?.protected) break;  // §8.3: inheritance stops here.
    }
    return chain;
  }
}

/**
 * The complete access check: the leaf decision plus the ancestor traverse
 * chain (§8.5).
 *
 * Returns {allowed, decisions, failedAt} — `failedAt` names the ancestor whose
 * traverse check failed, which is the single most useful thing to report when
 * a deep vault denies something unexpectedly.
 */
export function checkAccess({
  store, principals, principalId, path, rights,
  audience = 'gated', bypassTraverse = false, denyUnresolved = true,
}) {
  const targetIsFolder = isFolder(path);

  const leaf = evaluateChain({
    principals, principalId, chain: store.chainFor(path),
    rights, targetIsFolder, audience, denyUnresolved,
  });

  if (!bypassTraverse) {
    // Each ancestor's traverse is decided by its own chain; the checks
    // compose rather than flattening into one pass.
    const ancestors = ancestorFolders(targetIsFolder ? path.replace(/\/$/, '') + '/x' : path);
    for (const folder of ancestors) {
      if (folder === path) continue;
      const t = evaluateChain({
        principals, principalId, chain: store.chainFor(folder),
        rights: ['traverse'], targetIsFolder: true, audience, denyUnresolved,
      });
      if (!t.allowed) {
        const decisions = {};
        for (const r of rights) {
          decisions[r] = { decision: 'deny', by: t.decisions.traverse.by, failed_at: folder };
        }
        return { allowed: false, decisions, failedAt: folder, subjects: leaf.subjects };
      }
    }
  }

  return { ...leaf, failedAt: null };
}

/**
 * Effective rights for a principal on a path (§8.7) — the Windows "Effective
 * Access" equivalent, with the deciding ACE for each right. Without this an
 * inherited-deny misconfiguration deep in a tree is close to undiagnosable.
 */
export function effectiveRights({ store, principals, principalId, path, rights, ...opts }) {
  const result = checkAccess({
    store, principals, principalId, path,
    rights: rights ?? RIGHTS, ...opts,
  });
  const granted = Object.entries(result.decisions)
    .filter(([, d]) => d.decision === 'allow')
    .map(([r]) => r);
  return { ...result, granted };
}
