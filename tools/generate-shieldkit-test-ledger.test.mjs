import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import inventory from '../inventory/shieldkit-sdk-2ba14fd/subject-inventory.json' with { type: 'json' };
import {
  ShieldkitTestLedgerError,
  createShieldkitTestLedger,
  generateShieldkitTestLedger,
  LEDGER_SCHEMA,
} from './generate-shieldkit-test-ledger.mjs';

test('creates a deterministic exhaustive 274-test ledger with every authoritative classification', () => {
  const first = createShieldkitTestLedger(inventory);
  const second = createShieldkitTestLedger(structuredClone(inventory));
  assert.equal(first.schemaVersion, LEDGER_SCHEMA);
  assert.equal(first.counts.trackedTests, 274);
  assert.equal(first.counts.discoveredDomainTests, 240);
  assert.equal(first.counts.typecheckAssets, 1);
  assert.equal(first.counts.vendorExcludedTests, 33);
  assert.deepEqual(first, second);
  assert.deepEqual(first.runnerClassificationCounts, {
    'beta-product-portable-security': 29,
    'beta-runtime-qualification': 2,
    'external-fixture': 7,
    'external-verifier-source-qualification': 4,
    'local-covenant-qualification': 6,
    'local-depth4-campaign': 2,
    'local-strict-codec-campaign': 2,
    'local-verifier-lane-qualification': 16,
    'portable': 160,
    'q03-portable-support': 2,
    'q07-portable-support': 10,
    'typescript-compile-asset': 1,
    'vendor-excluded': 33,
  });
  assert.equal(new Set(first.tests.map((entry) => entry.source.path)).size, 274);
  assert.equal(new Set(first.tests.map((entry) => entry.testId)).size, 274);
  assert.equal(first.tests.filter((entry) => entry.runner.kind === 'domain-test').length, 240);
  assert.deepEqual(
    first.tests.filter((entry) => entry.runner.kind === 'domain-test').map((entry) => entry.source.path),
    inventory.domainTests.map((entry) => entry.source.path).sort(),
  );
  // Fourteen pinned verifier-lane MJS tests are executed by the subject runner
  // but retain vendor scope; the remaining 33 are excluded upstream TS tests.
  assert.equal(first.tests.filter((entry) => entry.protocolScope === 'vendor').length, 47);
  assert.equal(first.tests.find((entry) => entry.source.path.endsWith('/packages/action/v2/typescript/codec.test.ts')).runner.classification, 'typescript-compile-asset');
  assert.equal(first.tests.find((entry) => entry.source.path.endsWith('/scripts/v2-q07-performance-harness.test.mjs')).promotability, 'nonpromotable-evidence-verifier');
  assert.equal(first.tests.find((entry) => entry.source.path.endsWith('/packages/profile/v2/beta-chipnet-runtime.test.mjs')).fixtureClass, 'private-runtime-artifact');
});

test('fails closed when an inventory test has no authoritative classification', () => {
  const malformed = structuredClone(inventory);
  malformed.domainTests = malformed.domainTests.slice(1);
  assert.throws(() => createShieldkitTestLedger(malformed), ShieldkitTestLedgerError);
});

test('fails closed when a discovered source hash or locked count drifts', () => {
  const wrongHash = structuredClone(inventory);
  wrongHash.domainTests[0].source.sha256 = '0'.repeat(64);
  assert.throws(() => createShieldkitTestLedger(wrongHash), /does not match tracked inventory/);
  const wrongCount = structuredClone(inventory);
  wrongCount.counts.trackedTestFiles = 273;
  assert.throws(() => createShieldkitTestLedger(wrongCount), /count contract differs/);
});

test('fails closed on an unknown runner classification and writes stable output from bytes', async (t) => {
  const malformed = structuredClone(inventory);
  malformed.domainTests[0].classification = 'misc';
  assert.throws(() => createShieldkitTestLedger(malformed), /unknown domain classification/);
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-test-ledger-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const input = path.join(directory, 'subject-inventory.json');
  const outputA = path.join(directory, 'a.json');
  const outputB = path.join(directory, 'b.json');
  await import('node:fs/promises').then(({ writeFile }) => writeFile(input, `${JSON.stringify(inventory, null, 2)}\n`));
  const first = generateShieldkitTestLedger({ inputPath: input, outputPath: outputA });
  const second = generateShieldkitTestLedger({ inputPath: input, outputPath: outputB });
  assert.equal(first.sha256, second.sha256);
  assert.deepEqual(await readFile(outputA), await readFile(outputB));
  assert.match(first.ledger.sourceInventorySha256, /^sha256:[0-9a-f]{64}$/u);
});
