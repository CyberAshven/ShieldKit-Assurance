# Policy

- Read historical source and immutable metadata only.
- Do not run a V1 broadcaster, mutate the playground, fetch a bundle, or treat
  a historical live transaction as new evidence.
- A valid pack graph means the historical boundary is well described. It never
  means that V1 is secure, audited, current, V2-compatible, production-ready,
  or release-qualified.
- The listed `git show` command is an inspection target only. It is not a test
  execution record or evidence that any historical behavior still works.
