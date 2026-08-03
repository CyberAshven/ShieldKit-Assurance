#!/usr/bin/env node
/**
 * Generate the immutable-subject test ledger. This deliberately consumes the
 * importer output rather than rediscovering a checkout: the ledger is a
 * reviewed classification of one exact subject inventory, not a second test
 * runner with a potentially different discovery surface.
 */
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const LEDGER_SCHEMA = 'shieldkit-assurance-test-ledger/v1';
export const SUBJECT_INVENTORY_SCHEMA = 'shieldkit-assurance-subject-inventory/v1';

const HASH = /^[0-9a-f]{64}$/u;
const TEST_PATH = /^03-create-your-own-pool\/.+\.test\.(?:mjs|ts)$/u;
const DOMAIN_CLASSIFICATIONS = new Set([
  'portable',
  'beta-product-portable-security',
  'q03-portable-support',
  'q07-portable-support',
  'external-fixture',
  'beta-runtime-qualification',
  'local-covenant-qualification',
  'local-verifier-lane-qualification',
  'external-verifier-source-qualification',
  'local-strict-codec-campaign',
  'local-depth4-campaign',
]);

export class ShieldkitTestLedgerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ShieldkitTestLedgerError';
  }
}

const fail = (message) => { throw new ShieldkitTestLedgerError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const stable = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(stable);
  const expected = [...keys].sort(stable);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has unexpected keys`);
  }
  return value;
};

function assertSource(source, label) {
  exactKeys(source, ['byteLength', 'path', 'sha256'], label);
  if (!TEST_PATH.test(source.path) || !Number.isSafeInteger(source.byteLength) || source.byteLength < 0 || !HASH.test(source.sha256)) {
    fail(`${label} is not a valid tracked test source`);
  }
  return source;
}

function protocolScopeFor(sourcePath) {
  if (sourcePath.includes('/vendor/')) return 'vendor';
  if (
    sourcePath.includes('/v2/')
    || sourcePath.includes('/internal/covenants/')
    || sourcePath.includes('/scripts/v2-')
    || sourcePath.endsWith('/scripts/setup-v2-native-prover.test.mjs')
  ) return 'v2';
  if (
    sourcePath.endsWith('/scripts/run-domain-tests.test.mjs')
    || sourcePath.endsWith('/scripts/run-rust-tests.test.mjs')
    || sourcePath.endsWith('/scripts/external-release-gate.test.mjs')
    || sourcePath.includes('/packages/profile/setup/')
    || sourcePath.endsWith('/packages/prove/authority.test.mjs')
    || sourcePath.endsWith('/packages/prove/fixed-point.test.mjs')
    || sourcePath.endsWith('/packages/prove/groth16.test.mjs')
  ) return 'shared';
  if (
    sourcePath.includes('/packages/action/')
    || sourcePath.includes('/packages/kit/')
    || sourcePath.includes('/packages/pool/')
    || sourcePath.includes('/packages/profile/')
    || sourcePath.includes('/packages/prove/')
    || sourcePath.includes('/packages/recover/')
  ) return 'v1';
  fail(`no protocol-scope mapping for ${sourcePath}`);
}

function claimCategoriesFor(protocolScope, runnerClassification) {
  if (runnerClassification === 'typescript-compile-asset') return ['claim.v2.typescript-codec-typecheck'];
  if (runnerClassification === 'vendor-excluded') return ['claim.vendor.upstream-excluded'];
  const special = {
    'beta-product-portable-security': 'claim.v2.beta-product-security-boundary',
    'q03-portable-support': 'claim.v2.q03-evidence-verifier-support',
    'q07-portable-support': 'claim.v2.q07-evidence-verifier-support',
    'external-fixture': 'claim.v2.external-fixture-boundary',
    'beta-runtime-qualification': 'claim.v2.private-runtime-fixture-boundary',
    'local-covenant-qualification': 'claim.v2.local-covenant-development',
    'local-verifier-lane-qualification': 'claim.v2.local-verifier-development',
    'external-verifier-source-qualification': 'claim.v2.external-verifier-source-availability',
    'local-strict-codec-campaign': 'claim.v2.strict-codec-local-campaign',
    'local-depth4-campaign': 'claim.v2.depth4-local-campaign',
  }[runnerClassification];
  if (special !== undefined) return [special];
  if (runnerClassification !== 'portable') fail(`no claim-category mapping for ${runnerClassification}`);
  return [
    protocolScope === 'v1' ? 'claim.v1.historical-regression'
      : protocolScope === 'v2' ? 'claim.v2.direct-local-regression'
        : protocolScope === 'shared' ? 'claim.shared.tooling-regression'
          : fail(`portable test cannot have protocol scope ${protocolScope}`),
  ];
}

function oracleIndependenceFor(sourcePath, runnerClassification) {
  if (runnerClassification === 'vendor-excluded') return 'upstream-vendor-unassessed';
  if (runnerClassification === 'typescript-compile-asset') return 'compiler-only';
  if (runnerClassification === 'external-fixture') return 'external-artifact-fixture';
  if (runnerClassification === 'beta-runtime-qualification') return 'private-artifact-fixture';
  if (runnerClassification === 'local-covenant-qualification') return 'local-toolchain-oracle';
  if (runnerClassification === 'local-verifier-lane-qualification') return 'local-artifact-oracle';
  if (runnerClassification === 'external-verifier-source-qualification') return 'blocked-external-source';
  if (runnerClassification === 'q03-portable-support' || runnerClassification === 'q07-portable-support') return 'evidence-verifier-only';
  if (runnerClassification === 'local-strict-codec-campaign') return 'differential-same-vector';
  if (runnerClassification === 'local-depth4-campaign') return 'mixed-independent-and-shared-kernel';
  if (runnerClassification === 'beta-product-portable-security') return 'generated-fixture-self-oracle';
  if (sourcePath.includes('/independent-') || sourcePath.includes('/depth4-rust-certificate-checker.')) return 'independent-implementation';
  if (sourcePath.includes('/circuit-model.') || sourcePath.includes('/circuit-codec-vectors.')) return 'cross-implementation';
  if (sourcePath.includes('/evidence') || sourcePath.includes('/final-vm.')) return 'evidence-verifier-only';
  if (runnerClassification === 'portable') return 'self-oracle';
  fail(`no oracle-independence mapping for ${sourcePath}`);
}

function fixtureClassFor(sourcePath, runnerClassification) {
  if (runnerClassification === 'vendor-excluded') return 'vendor-managed';
  if (runnerClassification === 'typescript-compile-asset') return 'source-only';
  if (runnerClassification === 'external-fixture') return 'external-artifact';
  if (runnerClassification === 'beta-runtime-qualification') return 'private-runtime-artifact';
  if (runnerClassification === 'local-covenant-qualification') return 'materialized-local-toolchain';
  if (runnerClassification === 'local-verifier-lane-qualification') return 'materialized-local-artifact';
  if (runnerClassification === 'external-verifier-source-qualification') return 'missing-external-source';
  if (runnerClassification === 'beta-product-portable-security') return 'generated-private';
  if (runnerClassification === 'q03-portable-support') return 'test-only-lane-envelope';
  if (runnerClassification === 'q07-portable-support') return 'test-only-nonqualifying';
  if (runnerClassification === 'local-strict-codec-campaign' || runnerClassification === 'local-depth4-campaign') return 'deterministic-generated';
  if (sourcePath.includes('/raw-chain-') || sourcePath.includes('/raw-settlement-')) return 'tracked-public-raw';
  if (runnerClassification === 'portable') return 'contained-test-fixture';
  fail(`no fixture-class mapping for ${sourcePath}`);
}

function ciSuitesFor(runnerClassification) {
  const suites = {
    portable: ['ci.unit'],
    'beta-product-portable-security': ['ci.unit', 'ci.beta-product-security'],
    'q03-portable-support': ['ci.unit'],
    'q07-portable-support': ['ci.unit'],
    'local-strict-codec-campaign': ['ci.strict-codec-campaign'],
    'local-depth4-campaign': ['ci.depth4-campaign'],
    'local-covenant-qualification': ['ci.local-covenants'],
    'local-verifier-lane-qualification': ['ci.local-verifier-lane'],
    'typescript-compile-asset': ['ci.typescript'],
    'external-fixture': [],
    'beta-runtime-qualification': [],
    'external-verifier-source-qualification': [],
    'vendor-excluded': [],
  }[runnerClassification];
  if (suites === undefined) fail(`no CI-suite mapping for ${runnerClassification}`);
  return suites;
}

function promotabilityFor(runnerClassification) {
  const value = {
    portable: 'regression-only',
    'beta-product-portable-security': 'regression-only',
    'q03-portable-support': 'nonpromotable-evidence-verifier',
    'q07-portable-support': 'nonpromotable-evidence-verifier',
    'external-fixture': 'blocked-external-fixture',
    'beta-runtime-qualification': 'blocked-private-fixture',
    'local-covenant-qualification': 'local-development-only',
    'local-verifier-lane-qualification': 'local-development-only',
    'external-verifier-source-qualification': 'blocked-missing-external-source',
    'local-strict-codec-campaign': 'bounded-local-only',
    'local-depth4-campaign': 'bounded-local-only',
    'typescript-compile-asset': 'compile-only',
    'vendor-excluded': 'not-subject-evidence',
  }[runnerClassification];
  if (value === undefined) fail(`no promotability mapping for ${runnerClassification}`);
  return value;
}

function testIdFor(sourcePath) {
  return `shieldkit-sdk-2ba14fd:${sourcePath}`;
}

function addRecord(records, source, runnerClassification, runnerReason, runnerKind) {
  assertSource(source, `${runnerKind} source`);
  const protocolScope = protocolScopeFor(source.path);
  const record = Object.freeze({
    testId: testIdFor(source.path),
    source: Object.freeze({ path: source.path, sha256: `sha256:${source.sha256}`, byteLength: source.byteLength }),
    runner: Object.freeze({ kind: runnerKind, classification: runnerClassification, reason: runnerReason }),
    evidenceClass: runnerClassification === 'vendor-excluded' ? 'vendor-upstream-excluded'
      : runnerClassification === 'typescript-compile-asset' ? 'typecheck-asset'
        : runnerClassification,
    protocolScope,
    claimCategoryIds: Object.freeze(claimCategoriesFor(protocolScope, runnerClassification)),
    oracleIndependence: oracleIndependenceFor(source.path, runnerClassification),
    fixtureClass: fixtureClassFor(source.path, runnerClassification),
    ciSuites: Object.freeze(ciSuitesFor(runnerClassification)),
    promotability: promotabilityFor(runnerClassification),
  });
  if (records.has(source.path)) fail(`test source is registered more than once: ${source.path}`);
  records.set(source.path, record);
}

function assertInventory(inventory) {
  exactKeys(inventory, [
    'cashSources', 'ciWorkflows', 'circomSources', 'counts', 'domainTests', 'ignoredScopes', 'leanSources',
    'rustTestSources', 'schemaVersion', 'subject', 'trackedTests', 'typecheckAssets',
  ], 'subject inventory');
  if (inventory.schemaVersion !== SUBJECT_INVENTORY_SCHEMA) fail(`unsupported subject inventory schema: ${inventory.schemaVersion}`);
  exactKeys(inventory.subject, ['repository', 'revision', 'tree'], 'subject inventory.subject');
  if (typeof inventory.subject.repository !== 'string' || !/^[0-9a-f]{40}$/u.test(inventory.subject.revision) || !/^[0-9a-f]{40}$/u.test(inventory.subject.tree)) fail('subject inventory identity is malformed');
  exactKeys(inventory.counts, [
    'discoveredDomainTests', 'rustIgnoredDeclarations', 'rustTestDeclarations', 'trackedFiles',
    'trackedMjsTests', 'trackedTestFiles', 'trackedTsTests', 'typecheckAssets',
  ], 'subject inventory.counts');
  if (
    inventory.counts.trackedTestFiles !== 274
    || inventory.counts.trackedMjsTests !== 240
    || inventory.counts.trackedTsTests !== 34
    || inventory.counts.discoveredDomainTests !== 240
    || inventory.counts.typecheckAssets !== 1
  ) fail('subject inventory count contract differs from the locked ShieldKit subject');
  if (!Array.isArray(inventory.trackedTests) || !Array.isArray(inventory.domainTests) || !Array.isArray(inventory.typecheckAssets)) fail('subject inventory test collections are malformed');
  return inventory;
}

/** Create a complete fail-closed ledger from an imported immutable subject. */
export function createShieldkitTestLedger(inventory, { inventorySha256 = undefined } = {}) {
  assertInventory(inventory);
  const tracked = new Map();
  for (const source of inventory.trackedTests) {
    assertSource(source, 'trackedTests entry');
    if (tracked.has(source.path)) fail(`trackedTests contains duplicate source: ${source.path}`);
    tracked.set(source.path, source);
  }
  if (tracked.size !== inventory.counts?.trackedTestFiles || tracked.size !== 274) {
    fail(`tracked test count must be exactly 274, got ${tracked.size}`);
  }
  const records = new Map();
  for (const entry of inventory.domainTests) {
    exactKeys(entry, ['classification', 'reason', 'relativePath', 'source'], 'domainTests entry');
    if (!DOMAIN_CLASSIFICATIONS.has(entry.classification)) fail(`unknown domain classification: ${entry.classification}`);
    if (!entry.relativePath.endsWith('.test.mjs') || entry.source.path !== `03-create-your-own-pool/${entry.relativePath}` || tracked.get(entry.source.path)?.sha256 !== entry.source.sha256) {
      fail(`domain test source does not match tracked inventory: ${entry.relativePath}`);
    }
    addRecord(records, entry.source, entry.classification, entry.reason, 'domain-test');
  }
  if (inventory.domainTests.length !== inventory.counts?.discoveredDomainTests || inventory.domainTests.length !== 240) {
    fail(`discovered domain test count must be exactly 240, got ${inventory.domainTests.length}`);
  }
  for (const entry of inventory.typecheckAssets) {
    exactKeys(entry, ['classification', 'reason', 'relativePath', 'source'], 'typecheckAssets entry');
    if (!entry.relativePath.endsWith('.test.ts') || entry.classification !== 'typescript-compile-asset' || entry.source.path !== `03-create-your-own-pool/${entry.relativePath}` || tracked.get(entry.source.path)?.sha256 !== entry.source.sha256) {
      fail(`typecheck asset does not match tracked inventory: ${entry.relativePath}`);
    }
    addRecord(records, entry.source, entry.classification, entry.reason, 'typecheck-asset');
  }
  if (inventory.typecheckAssets.length !== inventory.counts?.typecheckAssets || inventory.typecheckAssets.length !== 1) {
    fail(`typecheck asset count must be exactly 1, got ${inventory.typecheckAssets.length}`);
  }
  if (
    [...tracked.values()].filter((entry) => entry.path.endsWith('.test.mjs')).length !== 240
    || [...tracked.values()].filter((entry) => entry.path.endsWith('.test.ts')).length !== 34
  ) fail('tracked test extension counts differ from the locked ShieldKit subject');
  for (const source of tracked.values()) {
    if (records.has(source.path)) continue;
    if (!source.path.includes('/vendor/') || !source.path.endsWith('.test.ts')) {
      fail(`tracked test lacks an authoritative runner/typecheck classification: ${source.path}`);
    }
    addRecord(records, source, 'vendor-excluded', 'tracked vendored TypeScript upstream test; intentionally excluded from ShieldKit runner discovery', 'vendor-excluded');
  }
  if (records.size !== tracked.size) fail(`ledger coverage mismatch: records=${records.size} tracked=${tracked.size}`);
  const tests = [...records.values()].sort((left, right) => stable(left.source.path, right.source.path));
  const ids = new Set(tests.map((entry) => entry.testId));
  if (ids.size !== tests.length) fail('stable test IDs are not unique');
  const countBy = (field) => Object.fromEntries([...new Set(tests.map((entry) => entry[field]))].sort(stable).map((key) => [key, tests.filter((entry) => entry[field] === key).length]));
  const runnerCounts = Object.fromEntries([...new Set(tests.map((entry) => entry.runner.classification))].sort(stable).map((key) => [key, tests.filter((entry) => entry.runner.classification === key).length]));
  return Object.freeze({
    schemaVersion: LEDGER_SCHEMA,
    subject: Object.freeze({ ...inventory.subject }),
    sourceInventorySha256: inventorySha256 === undefined ? null : `sha256:${inventorySha256}`,
    counts: Object.freeze({ trackedTests: tests.length, discoveredDomainTests: inventory.domainTests.length, typecheckAssets: inventory.typecheckAssets.length, vendorExcludedTests: tests.filter((entry) => entry.runner.classification === 'vendor-excluded').length }),
    runnerClassificationCounts: Object.freeze(runnerCounts),
    evidenceClassCounts: Object.freeze(countBy('evidenceClass')),
    protocolScopeCounts: Object.freeze(countBy('protocolScope')),
    tests: Object.freeze(tests),
  });
}

export function generateShieldkitTestLedger({ inputPath, outputPath }) {
  if (typeof inputPath !== 'string' || typeof outputPath !== 'string') fail('inputPath and outputPath are required');
  const inputBytes = readFileSync(inputPath);
  const ledger = createShieldkitTestLedger(JSON.parse(inputBytes.toString('utf8')), { inventorySha256: sha256(inputBytes) });
  const bytes = Buffer.from(`${JSON.stringify(ledger, null, 2)}\n`, 'utf8');
  mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const temporary = `${outputPath}.tmp-${process.pid}`;
  writeFileSync(temporary, bytes, { mode: 0o600, flag: 'wx' });
  renameSync(temporary, outputPath);
  chmodSync(outputPath, 0o644);
  return Object.freeze({ outputPath, sha256: sha256(bytes), ledger });
}

function parseCli(argv) {
  if (argv.length !== 4 || argv[0] !== '--input' || argv[2] !== '--output') fail('usage: generate-shieldkit-test-ledger.mjs --input <subject-inventory.json> --output <test-ledger.json>');
  return Object.freeze({ inputPath: path.resolve(argv[1]), outputPath: path.resolve(argv[3]) });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const result = generateShieldkitTestLedger(parseCli(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify({ output: result.outputPath, sha256: `sha256:${result.sha256}`, counts: result.ledger.counts })}\n`);
}
