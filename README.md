# ShieldKit Assurance

ShieldKit Assurance is a protocol-neutral claim-to-evidence framework for
shielded protocol implementations. It treats qualification as a graph from a
public claim to explicit obligations, independent oracles, reproducible cases,
raw observations, and signed provenance.

The repository is under active construction. It currently makes no ShieldKit
V1, V2, Chipnet, production, audit, or release qualification claim. A stable
release is permitted only when the terminal requirements in
[`docs/TERMINAL_REQUIREMENTS.md`](docs/TERMINAL_REQUIREMENTS.md) are satisfied.

The initial commands are:

```text
shieldkit-assure pack validate <pack.json>
shieldkit-assure plan --pack <pack.json> --suite <suite-id>
shieldkit-assure schema pack
shieldkit-assure evidence verify <bundle-directory>
```

Protocol-specific code belongs in target repositories. The neutral core must
not import ShieldKit, BCH, Groth16, PF7, or PF10 implementation modules.
