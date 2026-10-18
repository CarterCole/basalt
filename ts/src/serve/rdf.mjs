// The linked-data surface, INTEROP §8.
//
// The link graph is the part of a vault that other systems most want and can
// least easily reconstruct, so it is also published as RDF: JSON-LD for
// anything JSON, Turtle for SPARQL stores and reasoners. A node's IRI is its
// gatekeeper URL, so the graph is dereferenceable — following an IRI lands on
// the node, with the same ACL check.
//
// The vocabulary lives under `urn:basalt:v1:` rather than an http namespace
// because this spec does not own a domain, and a URN cannot 404, move, or be
// taken over later. Where a standard term exists (title, identifier, extent)
// the standard one is used.

const NS = 'urn:basalt:v1:';
const DCTERMS = 'http://purl.org/dc/terms/';
const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';

const nodeIri = (base, path) =>
  `${base}/api/v1/node/${path.split('/').map(encodeURIComponent).join('/')}`;

const ttlString = (s) => '"' + String(s ?? '')
  .replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t') + '"';

/**
 * Build the graph for one principal.
 *
 * A redacted edge (§9.5) is not emitted as a triple — an RDF consumer has no
 * way to carry "there is an edge but you may not know to what" — so each node
 * instead carries a count of them. Dropping them silently would make the
 * published graph quietly wrong, which is the failure §9.5 exists to prevent.
 */
function graph(surface, principal, { base }) {
  const nodes = surface.nodes(principal);
  const byId = new Map(nodes.map((e) => [e.id, e]));
  return nodes.map((e) => {
    const edges = surface.links(principal, e.path);
    const linksTo = [];
    let redacted = 0;
    for (const edge of edges.out) {
      if (edge.to === 'redacted') { redacted++; continue; }
      const target = edge.to ? byId.get(edge.to) : null;
      if (target) linksTo.push(nodeIri(base, target.path));
    }
    return {
      iri: nodeIri(base, e.path),
      entry: e,
      linksTo: [...new Set(linksTo)].sort(),
      redacted,
      backlinks: edges.backlinks
        .filter((b) => b.path)
        .map((b) => nodeIri(base, b.path))
        .sort(),
    };
  });
}

export function jsonld(surface, principal, { base }) {
  const man = surface.manifest();
  const rows = graph(surface, principal, { base });
  return {
    '@context': {
      basalt: NS,
      dcterms: DCTERMS,
      path: `${NS}path`,
      kind: `${NS}kind`,
      contentHash: `${NS}contentHash`,
      tag: `${NS}tag`,
      redactedLinks: { '@id': `${NS}redactedLinks`, '@type': 'http://www.w3.org/2001/XMLSchema#integer' },
      linksTo: { '@id': `${NS}linksTo`, '@type': '@id' },
      backlinkFrom: { '@id': `${NS}backlinkFrom`, '@type': '@id' },
      title: `${DCTERMS}title`,
      identifier: `${DCTERMS}identifier`,
      extent: { '@id': `${DCTERMS}extent`, '@type': 'http://www.w3.org/2001/XMLSchema#integer' },
      vault: { '@id': `${NS}inVault`, '@type': '@id' },
    },
    '@id': `${base}/api/v1/manifest`,
    '@type': `${NS}Vault`,
    identifier: man.vault.id,
    title: man.vault.title ?? man.vault.id,
    '@graph': rows.map((r) => ({
      '@id': r.iri,
      '@type': `${NS}Node`,
      identifier: r.entry.id,
      title: r.entry.title,
      path: r.entry.path,
      kind: r.entry.kind,
      contentHash: r.entry.content_hash,
      extent: r.entry.size ?? 0,
      tag: r.entry.tags ?? [],
      linksTo: r.linksTo,
      backlinkFrom: r.backlinks,
      redactedLinks: r.redacted,
      vault: `${base}/api/v1/manifest`,
    })),
  };
}

export function turtle(surface, principal, { base }) {
  const man = surface.manifest();
  const rows = graph(surface, principal, { base });
  const out = [
    `@prefix basalt: <${NS}> .`,
    `@prefix dcterms: <${DCTERMS}> .`,
    '@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .',
    '',
    `# Basalt vault ${man.vault.id}, as visible to this principal (INTEROP §8).`,
    `<${base}/api/v1/manifest> a basalt:Vault ;`,
    `  dcterms:identifier ${ttlString(man.vault.id)} ;`,
    `  dcterms:title ${ttlString(man.vault.title ?? man.vault.id)} .`,
    '',
  ];
  for (const r of rows) {
    // Each line is one predicate-object pair; the separators go in at the
    // join so a node with no tags or edges still terminates correctly.
    const lines = [
      '  a basalt:Node',
      `  dcterms:identifier ${ttlString(r.entry.id)}`,
      `  dcterms:title ${ttlString(r.entry.title)}`,
      `  basalt:path ${ttlString(r.entry.path)}`,
      `  basalt:kind ${ttlString(r.entry.kind)}`,
      `  basalt:contentHash ${ttlString(r.entry.content_hash)}`,
      `  dcterms:extent "${r.entry.size ?? 0}"^^xsd:integer`,
      `  basalt:inVault <${base}/api/v1/manifest>`,
      `  basalt:redactedLinks "${r.redacted}"^^xsd:integer`,
    ];
    for (const t of r.entry.tags ?? []) lines.push(`  basalt:tag ${ttlString(t)}`);
    for (const to of r.linksTo) lines.push(`  basalt:linksTo <${to}>`);
    for (const from of r.backlinks) lines.push(`  basalt:backlinkFrom <${from}>`);
    out.push(`<${r.iri}>`, lines.join(' ;\n') + ' .', '');
  }
  return out.join('\n');
}

export const RDF_NS = { NS, DCTERMS, RDF };
