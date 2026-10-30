# Changelog

## Unreleased

- Explain each terminal menu action and its cloud/local effects; add first-time local tenant setup with explicit scope selection, optional Reader starter template, cancellation, duplicate protection and unchanged Azure activation policies.

- Add optional persistent numbered terminal menu (-Tui): account search, profile preview/apply, eligibility export, offline browsing/backups and recent reports. Keep existing CLI commands, Graph sign-in off by default, and require exact target confirmation after preview.

- Correct activation inspection to report-only by default; remove assistant-added Odyssey requirements. Readable settings are Observed. Additional MFA, approval, or duration restrictions require explicit configuration.

- Add ARM-only activation policy checks for Azure-resource profiles: explicit MFA, approval with configured primary approvers, expiration, and an optional activation-duration ceiling. These restrictions are opt-in; unreadable checks remain blocked. Recheck before grants.
- Add automatic and manual byte-preserving local tenant/profile snapshots with verified hashes and manifests; keep snapshots git-ignored.
- Remove the unused subscription sweep from exact-scope profile workflows while retaining per-scope tenant validation.
- Exercise live read-only preview behavior; the local tenant ARM check was blocked by certificate-chain validation and correctly recorded Unknown without writes.

- Generate export display names and descriptions from actual roles, scopes, and expiry terms.
- Add opt-in direct management-group discovery, explicit additional ARM scopes, and group-derived access evidence without converting indirect access into direct grants.
- Share exact-identity/scope/date verification and durable per-assignment outcome journals across both profile commands; retain request receipts, failures, observed assignment IDs, and actual dates.
- Reject mismatched or unverified outcomes; retry only reads. Preserve existing eligibility without silent renewal.
- Support broader guided imports and evidence-only reports, and add offline coverage/audit/launcher regressions for PowerShell 5.1 and 7.

- Add a guided template workflow with exact-account confirmation, metadata review/version lifecycle, approved scope bindings, role selection and selected Azure-resource reference imports.
- Add per-grant journals, Azure resource request receipts, independent provisioning readback and scoped comparison/expiry reports.
- Add synthetic template metadata, a portable JSON example and mocked workflow regression tests for PowerShell 5.1 and 7.
- Template review is operator attestation; no live provisioning or external approval integration is claimed.

- Add read-only eligibility export to tenant-local PSD1 profiles, defaulting to Azure resources, with optional Graph group/Entra-role planes and recorded discovery coverage.
- Preserve finite source expiry by default; allow an explicit fresh bounded duration. Refuse conditional, incomplete, conflicting, empty, or malformed exports and existing destinations.
- Add Azure-resource eligibility profile preview/apply and stable group/directory IDs; validate exported expiration policies at planning and write time.
- Add offline export/profile round-trip tests in PowerShell 5.1 and 7. No live grants were exercised.

- Accept Azure CLI subscription-list `cloudName` metadata as well as `environmentName`; reject missing or conflicting metadata and preserve tenant/cloud filtering.

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
