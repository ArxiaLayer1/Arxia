# Security-review identifiers

Comments and documentation across this repository reference finding
identifiers of the form `CRIT-NNN`, `HIGH-NNN`, `MED-NNN` and
`LOW-NNN`.

These reference an **internal security review** conducted before and
during the public release of this codebase. The identifiers follow the
standard severity taxonomy (critical / high / medium / low, numbered
per finding). The review's register — the document mapping each
identifier to its full finding — is internal and not published; the
code comment at each referencing site describes the finding it closes,
which is the part a reader needs.

The published third-party audit of the ARX ERC-20 token contract is a
separate engagement with its own report and does not use these
identifiers.

The internal review predates the public consolidation of this
repository's git history. Narrative references to the review's own
commit numbering were removed for that reason: those numbers do not
resolve against the published history, and the finding identifiers
alone carry the traceability.
