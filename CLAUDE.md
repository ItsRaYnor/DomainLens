# Conventions for this repository

## Versioning

`VERSION` drives the Docker tag published alongside `latest`, so the number is
how a rollback is aimed. Two rules follow from that.

**Increment the patch digit.** `0.0.1` → `0.0.2` → `0.0.3`. A bug fix, a new
check, a new panel — all of it is a patch. Do not bump the minor for a feature
just because it feels sizeable; several minor bumps in a day says nothing
useful about what changed.

Raise the minor only when an operator has to do something to keep working:
a new required environment variable, a changed default that alters behaviour,
a removed endpoint. Raise the major only for a migration that cannot be
reversed.

**Never lower it.** Published tags are immutable and someone may be pinned to
one. A number that goes backwards while the code goes forwards makes the tag
lie about its contents, and the rollback path stops being trustworthy.

The count was reset to `0.0.1` once, when the tool was renamed from NetProbe to
DomainLens. That is not an exception to the rule above but a consequence of it:
the image name changed at the same time, so `domainlens:0.0.1` is the first tag
in a repository that has never published anything. No existing tag was
overwritten and nothing anyone had pinned changed meaning. A reset is only ever
sound on those terms — a new image name, starting empty.

## Tests

Every behaviour change comes with a test that fails without it. Test names and
docstrings say what went wrong and why it mattered, not what the function does.

## Reporting

An absent or unverifiable answer is never presented as a clean one, and never
as a defect of the scanned domain either. Three distinct states, kept apart:
measured, could not be measured, and deliberately not applicable. Advice the
operator cannot act on without breaking their own site does not belong in the
findings list.
