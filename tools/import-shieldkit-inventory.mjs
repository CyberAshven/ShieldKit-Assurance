#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const args = Object.fromEntries(Array.from({ length: process.argv.length - 2 }, (_, index) => index)
  .filter((index) => process.argv[index + 2]?.startsWith('--'))
  .map((index) => [process.argv[index + 2], process.argv[index + 3]]));
const source = args['--source'];
const output = args['--output'];
const expectedRevision = args['--expected-revision'];
const expectedTree = args['--expected-tree'];
if (!source || !output || !expectedRevision || !expectedTree) {
  throw new Error('usage: import-shieldkit-inventory.mjs --source <clean-checkout> --output <new-json> --expected-revision <40hex> --expected-tree <40hex>');
}
const root = path.resolve(source);
const destination = path.resolve(output);
const git = (...gitArgs) => execFileSync('git', ['-C', root, ...gitArgs], { encoding: 'utf8' }).trim();
const revision = git('rev-parse', 'HEAD');
const tree = git('rev-parse', 'HEAD^{tree}');
if (revision !== expectedRevision || tree !== expectedTree) {
  throw new Error(`subject differs: revision=${revision} tree=${tree}`);
}
if (git('status', '--porcelain') !== '') {
  throw new Error('subject checkout is not clean');
}
const tracked = execFileSync('git', ['-C', root, 'ls-files', '-z'])
  .toString('utf8').split('\0').filter(Boolean).sort();
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fileRecord = (relativePath) => {
  const absolute = path.join(root, relativePath);
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error(`tracked inventory input must be one regular single-link file: ${relativePath}`);
  }
  const bytes = readFileSync(absolute);
  return { path: relativePath, byteLength: bytes.length, sha256: sha256(bytes) };
};
const runnerUrl = pathToFileURL(path.join(root, '03-create-your-own-pool/scripts/run-domain-tests.mjs')).href;
const { discoverDomainTests } = await import(runnerUrl);
const discovery = discoverDomainTests();
const normalizeTest = (test) => ({
  relativePath: test.relativePath,
  classification: test.classification,
  reason: test.reason,
  source: fileRecord(`03-create-your-own-pool/${test.relativePath}`),
});
const trackedTests = tracked.filter((entry) => /\.test\.(?:mjs|ts)$/u.test(entry));
const rustSources = tracked.filter((entry) => entry.endsWith('.rs')).map((entry) => {
  const text = readFileSync(path.join(root, entry), 'utf8');
  return {
    ...fileRecord(entry),
    testDeclarations: (text.match(/#\s*\[\s*test\s*\]/gu) ?? []).length,
    ignoredDeclarations: (text.match(/#\s*\[\s*ignore(?:\s|\(|\])/gu) ?? []).length,
  };
}).filter((entry) => entry.testDeclarations > 0 || entry.ignoredDeclarations > 0);
const result = {
  schemaVersion: 'shieldkit-assurance-subject-inventory/v1',
  subject: {
    repository: git('remote', 'get-url', 'origin'),
    revision,
    tree,
  },
  counts: {
    trackedFiles: tracked.length,
    trackedTestFiles: trackedTests.length,
    trackedMjsTests: trackedTests.filter((entry) => entry.endsWith('.test.mjs')).length,
    trackedTsTests: trackedTests.filter((entry) => entry.endsWith('.test.ts')).length,
    discoveredDomainTests: discovery.tests.length,
    typecheckAssets: discovery.typecheckAssets.length,
    rustTestDeclarations: rustSources.reduce((sum, entry) => sum + entry.testDeclarations, 0),
    rustIgnoredDeclarations: rustSources.reduce((sum, entry) => sum + entry.ignoredDeclarations, 0),
  },
  domainTests: discovery.tests.map(normalizeTest),
  typecheckAssets: discovery.typecheckAssets.map(normalizeTest),
  ignoredScopes: discovery.ignoredScopes,
  trackedTests: trackedTests.map(fileRecord),
  rustTestSources: rustSources,
  leanSources: tracked.filter((entry) => entry.endsWith('.lean')).map(fileRecord),
  circomSources: tracked.filter((entry) => entry.endsWith('.circom')).map(fileRecord),
  cashSources: tracked.filter((entry) => entry.endsWith('.cash')).map(fileRecord),
  ciWorkflows: tracked.filter((entry) => entry.startsWith('.github/workflows/') && /\.ya?ml$/u.test(entry)).map(fileRecord),
};
mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
const temporary = `${destination}.tmp-${process.pid}`;
writeFileSync(temporary, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
renameSync(temporary, destination);
chmodSync(destination, 0o644);
process.stdout.write(`${JSON.stringify({ output: destination, sha256: sha256(readFileSync(destination)), counts: result.counts })}\n`);
