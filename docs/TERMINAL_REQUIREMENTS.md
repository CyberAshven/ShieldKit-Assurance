# Terminal requirements

The first stable ShieldKit Assurance release is one indivisible terminal
program. Internal commits and dependency stages are not reduced deliverables.

Completion requires all of the following:

1. A standalone public framework with a hermetic runner, stable schemas, CLI,
   TypeScript SDK, evidence/provenance verification, independent oracles,
   generators and shrinking, fuzzing, mutation testing, formal models,
   deterministic fault simulation, privacy and side-channel analysis, CI, and
   offline reporting.
2. A complete migration ledger for every tracked ShieldKit Node, Rust, Lean,
   circuit, covenant, campaign, evidence, external-gate, and CI test at the
   immutable subject revision. The previous runner is retired only after exact
   clean-worktree parity and proof that no test was omitted.
3. A frozen V1/PF7 historical-conformance pack. It cannot broadcast, mutate the
   live pool, become release eligible, or contribute to V2 qualification.
4. A complete V2 Direct pack with every normative claim, nonclaim, hard limit,
   security requirement, audit scope, clean-host requirement, and live scenario
   represented by mandatory evidence obligations.
5. V2 protocol, implementation, audit, and Chipnet qualification. Setup trust is
   reported independently; a multi-party ceremony is optional and a verified
   single-contributor setup never claims participant independence.
6. Coverage-driven zero-confirmation Chipnet qualification using public TLS
   providers and exactly-once broadcast. There is no confirmation wait, no
   30-day soak, no sponsor, no faucet, no credentialed private RPC, and no
   mainnet path.
7. Full BCH hard ceilings: every transaction at most 100,000 bytes, every input
   unlock at most 10,000 bytes, and every VM resource at most 100 percent.
   Narrower byte margins are telemetry, never substituted limits.
8. One complete 100,000-action scale history and no million-action requirement.
9. No placeholder, toy substitute, synthetic qualification evidence, fake
   backend, opaque Boolean closure, unexplained skip, waived failure, surviving
   relevant mutant, or unsupported claim.
10. Reproducible builds and evidence on independent clean hosts, signed and
    hash-pinned release artifacts, complete SBOM and provenance, and a
    requirement-by-requirement final completion audit.

The authoritative ShieldKit subject begins at repository
`git@github.com:toorik2/ShieldKit-SDK.git`, commit
`2ba14fd7d1d5d0acdd49b97ea3ee77b8ab0ea854`, tree
`6023d6504e2958efced6906b34f523eebc5147ce`. Any subject revision change must be
recorded in a new lock and invalidates evidence whose source binding changes.
