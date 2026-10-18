// Principals and NTFS-style access control, PROTOCOL §7 and §8.

import { ancestorFolders, isFolder, parentFolder, basename } from './keys.mjs';

/** Every right (§8.1). `full_control` expands to this list. */
export const RIGHTS = [
  'read', 'list', 'traverse', 'comment', 'write', 'create_child',
  'delete', 'delete_child', 'read_acl', 'write_acl', 'take_ownership',
  'read_history', 'publish',
];

export const WELL_KNOWN = new Set([
  'everyone', 'anonymous', 'authenticated', 'owner', 'system',
]);

export const DEFAULT_ROLES = {
  reader: ['read', 'list', 'traverse'],
  commenter: ['read', 'list', 'traverse', 'comment'],
  editor: ['read', 'list', 'traverse', 'comment', 'write', 'create_child', 'delete_child'],
  owner: ['full_control'],
  auditor: ['read', 'list', 'traverse', 'read_acl', 'read_history'],
};

/**
 * Principal directory: users, groups and roles, with transitive membership.
 */
export class Principals {
  constructor({ users = [], groups = [], roles = {} } = {}) {
    this.users = new Map(users.map((u) => [u.id, u]));
    this.groups = new Map(groups.map((g) => [g.id, g]));
    this.roles = { ...DEFAULT_ROLES, ...roles };
    this.integrity = [];
    this.#validate();
    this.#cache = new Map();
  }

  #cache;

  #validate() {
    for (const id of [...this.users.keys(), ...this.groups.keys()]) {
      if (WELL_KNOWN.has(id)) {
        this.integrity.push({
          severity: 'error', code: 'RESERVED_PRINCIPAL_ID', subject: id,
        });
      }
    }
    // Detect membership cycles once, up front (§7.2).
    for (const id of this.groups.keys()) {
      if (this.#hasCycle(id, new Set())) {
        this.integrity.push({ severity: 'error', code: 'GROUP_CYCLE', subject: id });
      }
    }
  }

  #hasCycle(id, seen) {
    if (seen.has(id)) return true;
    const g = this.groups.get(id);
    if (!g) return false;
    seen.add(id);
    for (const m of g.members ?? []) {
      if (this.groups.has(m) && this.#hasCycle(m, new Set(seen))) return true;
    }
    return false;
  }

  /** True when the id names a known user, group or well-known principal. */
  exists(id) {
    return WELL_KNOWN.has(id) || this.users.has(id) || this.groups.has(id);
  }

  /** Is this user active? Suspended and expired both count as inactive (§7.1). */
  isActive(userId) {
    const u = this.users.get(userId);
    if (!u) return false;
    if (u.status && u.status !== 'active') return false;
    if (u.expires && new Date(u.expires).getTime() <= Date.now()) return false;
    return true;
  }

  /**
   * Every group reachable from a principal, transitively (§7.2). Cycle-safe:
   * a cycle must still terminate and yield the reachable set, never hang.
   */
  groupsOf(principalId) {
    if (this.#cache.has(principalId)) return this.#cache.get(principalId);
    const out = new Set();
    const seen = new Set();
    const walk = (id) => {
      if (seen.has(id)) return;
      seen.add(id);
      for (const [gid, g] of this.groups) {
        if ((g.members ?? []).includes(id)) {
          if (!out.has(gid)) { out.add(gid); walk(gid); }
        }
      }
    };
    walk(principalId);
    this.#cache.set(principalId, out);
    return out;
  }

  /** Expand a rights list, resolving roles and full_control (§7.4, §8.1). */
  expandRights(rights) {
    const out = new Set();
    const unresolved = [];
    for (const r of rights ?? []) {
      if (r === 'full_control') { for (const x of RIGHTS) out.add(x); continue; }
      if (RIGHTS.includes(r)) { out.add(r); continue; }
      if (this.roles[r]) {
        for (const x of this.expandRights(this.roles[r]).rights) out.add(x);
        continue;
      }
      unresolved.push(r);
    }
    return { rights: out, unresolved };
  }
}

/**
 * The subject set for a request (§8.4 step 1): the principal, its transitive
 * groups, the applicable well-known principals, and `owner` when it owns the
 * object being tested.
 *
 * Computed per object, because `owner` depends on which object is being
 * evaluated — an ancestor's traverse check uses that ancestor's owner.
 */
export function subjectSet(principals, principalId, owner) {
  const s = new Set([principalId, 'everyone']);
  const anon = principalId === 'anonymous';

  if (anon) {
    s.add('anonymous');
  } else if (principals.isActive(principalId)) {
    s.add('authenticated');
    for (const g of principals.groupsOf(principalId)) s.add(g);
  }
  // A suspended user keeps only its own id and `everyone`, so that denies
  // naming it still bite while its group-derived allows vanish (§7.1).

  if (owner && owner === principalId) s.add('owner');
  return s;
}

/**
 * Evaluate a request against a descriptor chain.
 *
 * `chain` is ordered nearest-first: the object's own descriptor, then its
 * parent folder's, and so on, already truncated at the first `protected`.
 * Each element is {path, descriptor, distance}.
 *
 * Returns {decisions: {right: {decision, by}}, allowed: bool}.
 */
export function evaluateChain({
  principals, principalId, chain, rights, targetIsFolder,
  audience = 'gated', denyUnresolved = true,
}) {
  const own = chain[0]?.descriptor ?? {};
  const subjects = subjectSet(principals, principalId, own.owner);

  const candidates = [];
  let ceilingDropped = new Set();

  for (const { descriptor, distance } of chain) {
    const aces = descriptor?.dacl ?? [];
    for (let i = 0; i < aces.length; i++) {
      const ace = aces[i];
      const explicit = distance === 0;
      const flags = new Set(ace.flags ?? []);

      // §8.4 step 3: flag filtering.
      if (!explicit) {
        // An inherited ACE applies only if it carries the flag for this kind.
        if (targetIsFolder && !flags.has('ci')) continue;
        if (!targetIsFolder && !flags.has('oi')) continue;
        // `np` stops propagation past direct children.
        if (flags.has('np') && distance > 1) continue;
      } else if (flags.has('io')) {
        continue;  // inherit-only never applies to its carrier.
      }

      candidates.push({ ace, explicit, distance, order: i });
    }
  }

  // §8.4 step 4: four bands, then nearer ancestors first within a band.
  const band = (c) =>
    (c.explicit ? 0 : 2) + (c.ace.type === 'deny' ? 0 : 1);
  candidates.sort((a, b) =>
    band(a) - band(b) || a.distance - b.distance || a.order - b.order);

  const decisions = {};
  const requested = new Set(rights);

  // §12.2: the audience ceiling applies before the DACL and can only narrow.
  const anon = principalId === 'anonymous';
  if (anon && audience !== 'public') {
    for (const r of requested) {
      decisions[r] = { decision: 'deny', by: 'audience_ceiling' };
    }
    return { decisions, allowed: false, subjects: [...subjects] };
  }

  for (const r of requested) {
    let decided = null;
    for (const c of candidates) {
      const { ace } = c;

      if (!principals.exists(ace.subject)) {
        // §8.4: an unresolvable subject denies its rights when
        // security.deny_unresolved is true (the default and safe direction).
        const { rights: ar } = principals.expandRights(ace.rights);
        if (denyUnresolved && ar.has(r)) {
          decided = { decision: 'deny', by: ace.id ?? 'unresolved_subject' };
          break;
        }
        continue;
      }
      if (!subjects.has(ace.subject)) continue;

      // Under `private`, grants to `everyone` are ignored (§12.2).
      if (audience === 'private' && ace.subject === 'everyone' && ace.type === 'allow') {
        const { rights: ar } = principals.expandRights(ace.rights);
        if (ar.has(r)) ceilingDropped.add(r);
        continue;
      }

      // A suspended user loses its allows but keeps denies (§7.1).
      if (ace.type === 'allow' && !anon
          && principals.users.has(principalId) && !principals.isActive(principalId)) {
        continue;
      }

      const { rights: aceRights } = principals.expandRights(ace.rights);
      if (!aceRights.has(r)) continue;

      decided = {
        decision: ace.type === 'deny' ? 'deny' : 'allow',
        by: ace.id ?? `${ace.type}:${ace.subject}`,
      };
      break;  // §8.4 step 5: first match on this right decides it.
    }

    decisions[r] = decided ?? {
      decision: 'deny',
      by: ceilingDropped.has(r) ? 'audience_ceiling' : 'default',
    };
  }

  // §8.1: anonymous needs `publish` as well as `read`, so that "shared with
  // every account" and "on the public internet" stay different decisions.
  if (anon && requested.has('read') && decisions.read?.decision === 'allow') {
    const pub = evaluateChain({
      principals, principalId, chain, rights: ['publish'],
      targetIsFolder, audience: 'public', denyUnresolved,
    });
    if (pub.decisions.publish.decision !== 'allow') {
      decisions.read = { decision: 'deny', by: 'missing_publish' };
    }
  }

  const allowed = [...requested].every((r) => decisions[r].decision === 'allow');
  return { decisions, allowed, subjects: [...subjects] };
}
