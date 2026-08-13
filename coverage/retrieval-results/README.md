# Internal retrieval results

This directory retains the small canonical JSON result generated after an
assurance package has been downloaded from internal GitHub Actions staging and
verified independently of the package-creation job.

`coverage/archive-control.json` names the current result and records its
SHA-256.  `scripts/validate_coverage.py` resolves that reference, hashes the
generated JSON with LF-normalized line endings, validates its complete schema,
and checks its package ID, commit, tree, workflow run, manifest digest, file
count, byte count, and verification time against
`coverage/archive-retrieval.json`.

These records are internal staging traces.  They do not establish a controlled
external archive, retention or disposition authority, certification credit,
or authority acceptance.
