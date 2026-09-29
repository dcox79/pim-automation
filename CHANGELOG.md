# Changelog

## Unreleased

- Reconnect older Graph sessions missing group policy-read permission; preserve sufficient read/read-write sessions and fail closed on denied policy reads.

- Block standing membership in PIM-managed or unverifiable groups at planning and write time.
- Refuse incomplete relevant discovery, including active schedules, throttling, malformed data, and partial pages.
- Block conditional RBAC/resource-PIM copying and expiring active assignments instead of broadening access.
- Validate resolved profile role IDs, permissions, and canonical scopes; restrict custom standing roles to read-only permissions.
- Require explicit tenant binding for direct clone; validate public-cloud Graph/Azure context and target scope ownership.
- Preserve complete Graph scope sets and include group policy-read permission required by governance checks.
- Add offline behavioral regressions, including full mocked clone execution, in PowerShell 5.1 and 7.
- No live provisioning has been attempted; remaining P2 findings still apply.

## 0.1.0 - 2026-09-29

- Initial public preview of the full template and cloning project.
- Includes profile planning/apply, clone entry point, shared engine, and four synthetic profiles.
- Includes the operator runbook and documented unresolved safety findings.
- Includes 95 static source tests and 11 offline review probes for both PowerShell editions.
- Published from an allowlisted source snapshot without live tenant settings, credentials, audit exports, or prior local history.
- Release numbering is independent of existing script component versions, which are preserved.

Live provisioning has not been validated; this preview is not production-ready.
