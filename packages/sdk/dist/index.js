export const ADAPTER_PROTOCOL_V1 = 'shieldkit-assurance-adapter/v1';
const ID = /^[a-z0-9][a-z0-9._/-]*$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
export function validateAdapterRequest(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError('adapter request must be an object');
    }
    const request = value;
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
    return request;
}
