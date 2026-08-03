export const ADAPTER_PROTOCOL_V1 = 'shieldkit-assurance-adapter/v1' as const;

export type AdapterCapability =
  | 'describe'
  | 'canonicalize'
  | 'validate'
  | 'model.transition'
  | 'crypto.derive'
  | 'prove'
  | 'verify'
  | 'transaction.assemble'
  | 'vm.evaluate'
  | 'chain.observe'
  | 'store.step'
  | 'store.recover'
  | 'privacy.observe'
  | 'measure';

export interface BlobReference {
  readonly algorithm: 'sha256';
  readonly digest: string;
  readonly size: number;
  readonly mediaType: string;
  readonly secrecy: 'public' | 'secret';
}
export interface AdapterRequest {
  readonly protocol: typeof ADAPTER_PROTOCOL_V1;
  readonly requestId: string;
  readonly caseId: string;
  readonly capability: AdapterCapability;
  readonly seed: string;
  readonly publicInput: Readonly<Record<string, unknown>>;
  readonly blobs: readonly BlobReference[];
}

export interface AdapterObservation {
  readonly observationType: string;
  readonly publicValue: Readonly<Record<string, unknown>>;
  readonly artifacts: readonly BlobReference[];
  readonly metrics: Readonly<Record<string, number>>;
}

export type AdapterResponse =
  | {
      readonly protocol: typeof ADAPTER_PROTOCOL_V1;
      readonly requestId: string;
      readonly ok: true;
      readonly observations: readonly AdapterObservation[];
    }
  | {
      readonly protocol: typeof ADAPTER_PROTOCOL_V1;
      readonly requestId: string;
      readonly ok: false;
      readonly error: {
        readonly code: string;
        readonly message: string;
      };
    };

const ID = /^[a-z0-9][a-z0-9._/-]*$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export function validateAdapterRequest(value: unknown): AdapterRequest {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('adapter request must be an object');
  }
  const request = value as Partial<AdapterRequest>;
  const keys = Object.keys(request).sort();
  const expected = ['blobs', 'capability', 'caseId', 'protocol', 'publicInput', 'requestId', 'seed'];
  if (JSON.stringify(keys) !== JSON.stringify(expected)) {
    throw new TypeError('adapter request fields are not exact');
  }
  if (request.protocol !== ADAPTER_PROTOCOL_V1) {
    throw new TypeError('adapter protocol is unsupported');
  }
  if (typeof request.requestId !== 'string' || !ID.test(request.requestId)) {
    throw new TypeError('requestId is invalid');
  }
  if (typeof request.caseId !== 'string' || !ID.test(request.caseId)) {
    throw new TypeError('caseId is invalid');
  }
  if (typeof request.seed !== 'string' || request.seed.length === 0) {
    throw new TypeError('seed is invalid');
  }
  if (!Array.isArray(request.blobs)) {
    throw new TypeError('blobs must be an array');
  }
  for (const blob of request.blobs) {
    if (blob.algorithm !== 'sha256' || !SHA256.test(blob.digest)
      || !Number.isSafeInteger(blob.size) || blob.size < 0
      || (blob.secrecy !== 'public' && blob.secrecy !== 'secret')) {
      throw new TypeError('blob reference is invalid');
    }
  }
  return request as AdapterRequest;
}
