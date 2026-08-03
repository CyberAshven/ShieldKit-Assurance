# V2 Direct evidence policy

- The subject lock is exactly `2ba14fd7d1d5d0acdd49b97ea3ee77b8ab0ea854` and
  tree `6023d6504e2958efced6906b34f523eebc5147ce`. A source or artifact change
  requires a new pack revision and fresh final evidence.
- Beta/local, development-key, fixture, historical V1/PF7, and exploratory
  Chipnet results are context only. They cannot discharge any qualification
  obligation in this pack.
- Commands named in `pack.json` are proposed target adapters/backends, not an
  execution record. A command is promotable only through a new signed evidence
  bundle which binds this exact subject, final artifact root, raw artifacts, and
  the obligation-specific independent oracle results.
- Live qualification is public Chipnet, zero-confirmation, and coverage-driven:
  exact raw transaction and successor-state observations must cover required
  success, recovery, and negative routes. It has no 30-day or soak threshold.
- Mainnet is prohibited. A mainnet result is an invalid case, not additional
  evidence.
- Evidence must preserve raw artifacts and applicable signatures. Never replace
  failed gates with summaries, booleans, synthetic fixtures, skipped cases, or
  a narrower byte/resource limit.
- Release additionally requires all four independent audit areas and their
  signed closure. Setup trust is disclosed separately; it is never silently
  upgraded by successful proofs or by a beta ceremony.
