# Current ShieldKit subject

The immutable discovery subject is defined by
`subjects/shieldkit-sdk-2ba14fd.lock.json`. The checkout used to derive the
initial inventory was clean at commit `2ba14fd7` and tree `6023d650`.

Three subjects are deliberately non-interchangeable:

1. V1/PF7 historical: 80-byte `SHST` state, 752-byte `SCAR` packet, PF7
   carriers, and a preparation plus settlement topology. It is quarantined and
   cannot satisfy V2 obligations.
2. V2 Direct: 128-byte `SKS2` state, 552-byte `SDA2` packet, a depth-32 note
   tree and indexed-nullifier tree, and one direct self-funded settlement. Its
   provisional local topology is PF10; PF11 is an oracle-only design.
3. V2 beta: a real but explicitly unqualified single-contributor setup and
   exploratory Chipnet product bundle. Its local and live observations remain
   non-promotable until independently replayed against an immutable final
   subject.

The current runner discovers 240 Node `.test.mjs` files. Its default portable
selection is 201 files. The tracked repository also includes 34 `.test.ts`
files, three locked Rust crates, Lean gates, Circom sources, covenant tests, and
external qualification commands. This inventory is discovery evidence only;
green local tests do not establish protocol or release qualification.

The existing V2 live 5-deposit/5-withdrawal report predates the current subject
and explicitly fails the stated user-command performance gate. It cannot be
promoted or reused as exact-HEAD qualification evidence.
