import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { Surface } from '../src/serve/core.mjs';
import { graphql, printSchema } from '../src/serve/graphql.mjs';

const v = new Vault(new FsTransport(new URL('../../conformance/vaults/minimal/vault', import.meta.url).pathname));
await v.load();
await v.reindex();
const s = new Surface(v);

console.log(printSchema().split('\n').slice(0, 40).join('\n'));

const q = `query Look($p: String!) {
  manifest { vaultId title audience indexState }
  me { principal subjects }
  node(path: $p) { path title kind tags headings { level slug } text links { out { raw to target { title } } } }
  tree { folder title entries { path title } folders { folder entries { path } } }
  search(q: "columns") { total hits { score node { path } } }
  hidden: node(path: "Notes/Columns.md") { path title }
  recent(limit: 3) { path mtime }
  __typename
}`;
const r = await graphql({ source: q, variables: { p: 'Notes/Hexes.md' }, surface: s, principal: 'u:reader' });
console.log(JSON.stringify(r, null, 1).slice(0, 2600));

const intro = await graphql({ source: '{ __schema { queryType { name } types { name kind } directives { name locations } } }', surface: s, principal: 'u:reader' });
console.log('introspection types:', intro.data.__schema.types.length, 'err:', intro.errors ?? 'none');
const bad = await graphql({ source: '{ nope }', surface: s, principal: 'u:reader' });
console.log('bad:', JSON.stringify(bad));
const mut = await graphql({ source: 'mutation { x }', surface: s, principal: 'u:reader' });
console.log('mutation:', JSON.stringify(mut));
