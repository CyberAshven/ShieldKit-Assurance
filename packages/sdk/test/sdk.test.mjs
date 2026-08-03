import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ADAPTER_PROTOCOL_V1,
  validateAdapterRequest,
} from '../dist/index.js';

const request = () => ({
  protocol: ADAPTER_PROTOCOL_V1,
  requestId: 'request-1',
  caseId: 'case-1',
  capability: 'validate',
  seed: 'seed-1',
  publicInput: {},
  blobs: [{
    algorithm: 'sha256',
    digest: 'ab'.repeat(32),
    size: 4,
    mediaType: 'application/octet-stream',
    secrecy: 'public',
  }],
});
test('strict adapter request accepts the exact versioned frame', () => {
  assert.deepEqual(validateAdapterRequest(request()), request());
});

test('strict adapter request rejects extra fields and malformed blob references', () => {
  assert.throws(() => validateAdapterRequest({ ...request(), extra: true }), /fields are not exact/u);
  const malformed = request();
  malformed.blobs[0].digest = '00';
  assert.throws(() => validateAdapterRequest(malformed), /blob reference is invalid/u);
});
