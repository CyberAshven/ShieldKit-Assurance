# ShieldKit Assurance

ShieldKit Assurance is a protocol-neutral claim-to-evidence framework for
shielded protocol implementations. It treats qualification as a graph from a
public claim to explicit obligations, independent oracles, reproducible cases,
raw observations, and signed provenance.

The repository is under active construction. It currently makes no ShieldKit
V1, V2, Chipnet, production, audit, or release qualification claim. A stable
release is permitted only when the terminal requirements in
[`docs/TERMINAL_REQUIREMENTS.md`](docs/TERMINAL_REQUIREMENTS.md) are satisfied.

The implemented foundation currently includes:

- strict pack and adapter protocols;
- immutable, object-verified snapshots of pinned Git subjects;
- a closed-world evidence store and verifier;
- a network-isolated Bubblewrap execution sandbox;
- deterministic campaigns, replay, and shrinking;
- deterministic offline JSON, HTML, JUnit, and SARIF reports;
- fail-closed mutation, fault-simulation, and privacy-analysis engines;
- a frozen ShieldKit V1/PF7 historical pack, a V2 Direct obligations pack,
  and an exhaustive migration ledger for the pinned ShieldKit SDK subject.

These are framework capabilities, not qualification results. The runner,
independent-oracle integration, complete test migration, and live Chipnet
qualification remain required before any release verdict can be issued.

The initial commands are:

```text
shieldkit-assure pack validate <pack.json>
shieldkit-assure plan --pack <pack.json> --suite <suite-id>
shieldkit-assure schema pack
shieldkit-assure evidence verify <bundle-directory>
```

Protocol-specific code belongs in target repositories. The neutral core must
not import ShieldKit, BCH, Groth16, PF7, or PF10 implementation modules.
