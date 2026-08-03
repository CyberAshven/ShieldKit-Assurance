export declare const ADAPTER_PROTOCOL_V1: "shieldkit-assurance-adapter/v1";
export type AdapterCapability = 'describe' | 'canonicalize' | 'validate' | 'model.transition' | 'crypto.derive' | 'prove' | 'verify' | 'transaction.assemble' | 'vm.evaluate' | 'chain.observe' | 'store.step' | 'store.recover' | 'privacy.observe' | 'measure';
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
export type AdapterResponse = {
    readonly protocol: typeof ADAPTER_PROTOCOL_V1;
    readonly requestId: string;
    readonly ok: true;
    readonly observations: readonly AdapterObservation[];
} | {
    readonly protocol: typeof ADAPTER_PROTOCOL_V1;
    readonly requestId: string;
    readonly ok: false;
    readonly error: {
        readonly code: string;
        readonly message: string;
    };
};
export declare function validateAdapterRequest(value: unknown): AdapterRequest;
