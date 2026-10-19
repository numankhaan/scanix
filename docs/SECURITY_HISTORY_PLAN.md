# Historical exposure: proposed cleanup, not executed

Current-tree progress text has been sanitized. Forty-eight of the 63 initially
reachable commits contain a non-noreply personal identity, and old progress files
and 13 bytecode blobs contain personal home paths. The separately paused Phase 4A
head `d08659e` also needs its progress text sanitized before further publication.
Public GitHub-generated identities and synthetic loopback fixtures are intentional.
No actual production credential was identified by this audit.

A maintainer should privately review the retained findings and decide whether
historical privacy exposure warrants disruption. Do not publish the values or raw
reports. If a credential is subsequently confirmed, rotation/revocation takes
priority; history editing does not invalidate a credential.

If separately authorized: preserve a private access-controlled mirror/evidence,
inventory all affected refs/tags/PRs and external copies, agree a maintenance window,
prepare a filtered mirror with narrowly defined path/content/identity replacements,
validate all rewritten objects and signatures, and coordinate fresh clones and
hosting cache/PR-reference remediation with GitHub. Re-run the full secret/privacy
and regression checks. Assess forks, artifacts and backups separately; nobody can
guarantee complete recall of published material.

**No rewrite, force-push, artifact deletion, credential revocation or account-wide
setting change is part of this PR.** Future noreply commits do not repair history.
