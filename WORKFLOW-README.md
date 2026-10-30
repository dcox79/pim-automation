# Guided template workflow 1.0

Start here in PowerShell 7 (or Windows PowerShell 5.1):

```powershell
az login --tenant '<your-tenant-guid>'
.\scripts\cadm\Start-CadmWorkflow.ps1
```

The menu offers Preview, Apply, Compare/renewals, Build, Import reference user, and Review template.
Supply the exact CADM UPN or object ID. Prefix lookup is deliberately refused. Apply requires typing
`APPLY <exact-UPN>` after reviewing the account and assignments. Selecting Preview never enables writes.

## First use of existing templates

The synthetic example templates start as Draft. Create a private tenant binding before use. This
does not change any existing assignments. Use Review template to enter the owner, purpose,
reviewer, next review date and a higher version (for example 1.0.1). Read the displayed assignments
before marking REVIEWED. Review records operator attestation; it is not an external approval system.
The previous template is backed up before the metadata update. No access is granted by reviewing.

```powershell
.\scripts\cadm\Start-CadmWorkflow.ps1 -Action Review -ProfileName iaas-admin-jit
.\scripts\cadm\Start-CadmWorkflow.ps1 -Action Preview -ProfileName iaas-admin-jit -TargetUser admin@example.com -ConnectGraph:$false
.\scripts\cadm\Start-CadmWorkflow.ps1 -Action Apply -Apply -ProfileName iaas-admin-jit -TargetUser '<exact-target-UPN>' -ConnectGraph:$false
```

The example target is illustrative; substitute an existing account in your configured tenant.
A reviewed template with an expired review date is refused for apply. Drafts may be previewed and compared.

## Build or import a template

Choose Build for a new Azure-resource PIM template. Select a configured tenant scope, search the live
role catalog, choose numbered roles, enter a bounded ISO eligibility term, then record metadata.
Role selection creates PIM eligibility, with no standing assignments. Review the JSON summary before
saving. Filenames are validated and existing templates are never overwritten.

Built templates reference `template-scope`, separate from role definitions. Their default scope is a
configured tenant scope token. Change it at preview/apply using `-ScopeToken example-mg` (or another
configured token). Arbitrary scope arguments are refused. Add approved scope bindings to private
`tenant.psd1` when needed. Fixed-scope migrated or imported templates cannot be retargeted this way.

Choose Import to read a reference user's direct Azure-resource eligibilities and explicitly select
numbered entries. Import preserves exact scopes and finite expiry/future starts; it does not silently
turn copied expiry into a fresh year. This guided import currently covers Azure-resource eligibility
only. The legacy export entry point still supports opt-in group and directory planes. Private source
inventory is retained under the run output for traceability. Imports do not copy all effective access.

For automation/local template generation, Build also accepts a data-only JSON file:

```powershell
.\scripts\cadm\Start-CadmWorkflow.ps1 -Action Build -ProfileName workload-admin -ScopeToken example-mg -TemplateJson .\examples\resource-template.json
```

The supplied example is Draft; use Review before applying. New template versions should have new
filename keys when access definitions change; review can increment the metadata version in place.

## Verification and evidence

Each run writes a unique folder under `%LOCALAPPDATA%/PIM-Automation/workflow` (override with `-OutDir`).
`review.json` binds the exact account, actor, tenant, template version, configuration hashes, reviewed
policy-bounded terms, and plan. After typed confirmation, identity/configuration and the live plan
are checked again; changed plans are refused. This is an in-process reviewed plan, not a signed,
externally approved plan or replayable approval token.

Both profile entry points now share the same per-assignment journal and verification engine.
submissions.json is flushed before and after each write, including failures and available request
IDs. outcome.json records independent read-back evidence. Verification checks exact identity,
role or membership type, scope, and the dates actually submitted. Existing assignments are
Retained; new assignments are Verified only when the required evidence matches. Pending, Unknown,
and Mismatch are non-success outcomes, not permission to resubmit blindly.

The guided workflow additionally requires reviewed template metadata. The compatibility
Invoke-CadmAccess.ps1 -Mode profile command now has the same final-outcome audit and read-back
checks, while retaining its existing metadata and confirmation contract.

See [verification and broader coverage](handoff/profile-verification-and-coverage.md) for the
full audit schema, coverage flags, Graph permissions, and limitations. The Import action accepts
ExportPlanes, AdditionalScopes, IncludeManagementGroups, and IncludeGroupDerivedAccess;
operators still select individual direct eligibility entries before saving a template.

## Compare and renewal review

```powershell
.\scripts\cadm\Start-CadmWorkflow.ps1 -Action Compare -ProfileName iaas-admin-jit -TargetUser '<exact-target-UPN>' -ConnectGraph:$false
```

`comparison.json` shows missing expected entries plus present, scheduled, expiring (within 30 days),
expired and extra direct resource eligibilities at the template's exact scopes. Extra means outside
this template, not necessarily inappropriate. Group-based access, unrelated scopes, active/standing
access outside expected entries, and all effective permissions are not inventoried. No automatic
removal, renewal, scheduling or rollback is performed. Azure-resource activation policies are checked
in report-only mode unless local requirements are explicitly configured; group/directory activation policy and Conditional Access behavior are not evaluated.
Concurrent operators must coordinate; there is no distributed locking or transaction across grants.

## Offline validation

```powershell
python -B -m pytest -q -p no:cacheprovider tests
pwsh -NoProfile -File tests/Invoke-WorkflowTests.ps1
pwsh -NoProfile -File tests/identity/Invoke-P1SafetyTests.ps1
pwsh -NoProfile -File tests/identity/Invoke-ExportTests.ps1
```

Tests mock cloud transports. This new workflow has not been used for live provisioning or visually
accepted in a real interactive session. No live provisioning was performed during this build. Keep tenant bindings and runtime identity/access reports private.
