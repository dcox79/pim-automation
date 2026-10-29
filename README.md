# Guided template workflow

Use [Start-CadmWorkflow.ps1](scripts/cadm/Start-CadmWorkflow.ps1) for guided building/review, exact-account preview/apply, outcome verification and scoped comparison reports. See the [workflow guide](WORKFLOW-README.md). Only synthetic configuration is included. The legacy entry point below remains available.

# PIM Automation — templates and cloning

PowerShell tools to preview and grant access from reusable tenant profiles or an existing user's assignments.
This is the full provisioning project. The separate [PIM Eligibility Checker](https://github.com/dcox79/pim-eligibility-checker) only inspects eligibility.

**Preview — P1 fixes are under offline validation; P2 access-safety gaps remain.** Read the [project review](handoff/project-review.md) before using `-Apply`.
Offline tests do not establish safe live provisioning. Interactive clone mode implicitly enables writes.

## Included

- Tenant-specific, data-only PowerShell profile templates.
- Profile planning and apply for standing Azure RBAC, cloud group membership, and Azure-resource, group, and Entra-role PIM eligibility.
- Read-only export of user eligibilities into reusable tenant profiles, with explicit discovery coverage and preserved expiry.
- Automatic and interactive cloning, including Azure-resource eligibility discovery/copying.
- Four synthetic example profiles: Reader, Azure Owner JIT, Microsoft 365 admin JIT, and Global Administrator JIT.
- Operator runbook, known-issue review, static tests, and mocked review probes.

Profiles support direct Azure-resource eligibility through PimResourceEligibilities; clone mode does not copy directory-role eligibility.
See the [runbook](handoff/copy-cadm-access.md) for coverage and limitations.

## Requirements

- PowerShell 5.1 or 7; offline validation covers Windows PowerShell 5.1 and PowerShell 7 on Windows.
- Azure CLI and an authorized `az login` for the intended tenant.
- `Microsoft.Graph.Authentication`, appropriate Graph consent, and caller permissions for each operation.
- PIM availability and policies for the requested eligibility operations.
- Existing target accounts and, for cloning, an existing source account.
- A private tenant configuration with approved scopes and group mappings.

Python and pytest are needed only for the optional source tests.

## Configure and preview

Install the Graph authentication module once:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

Copy `scripts/cadm/tenants/example` to a private sibling folder. Replace the zero tenant GUID,
management-group scope, and `EXAMPLE_` group mappings with your approved configuration.
The supplied example cannot match a real tenant. Private tenant folders are ignored by Git;
keep a controlled backup separately.

```powershell
az login --tenant '<your-tenant-guid>'
.\scripts\cadm\Invoke-CadmAccess.ps1 -ListProfiles

# Preview a template:
.\scripts\cadm\Invoke-CadmAccess.ps1 -Mode profile -ProfileName reader-only -TargetUser target-admin@example.com

# Preview cloning an existing user:
.\scripts\Copy-CadmAccess.ps1 -TenantId '<your-tenant-guid>' -SourceUser source-admin@example.com -TargetUser target-admin@example.com
```

Normal profile/clone commands preview by default. After reviewing the plan and known issues,
`-Apply` enables grants and normally requires typing `APPLY`. `-Force` bypasses that confirmation.
Interactive mode enables apply implicitly. Apply is additive and does not roll back partial grants.

The launcher binds the configured tenant; direct cloning now requires an explicit `-TenantId`.
Azure and Graph operations require the same public-cloud tenant, and writes recheck scope ownership.
Incomplete relevant reads block apply. Conditional RBAC/resource-PIM assignments are reported as
`BLOCKED-CONDITIONAL` rather than copied without their restrictions. Standing group grants recheck
PIM policy and reject PIM-managed, role-assignable, synced, dynamic, or unverifiable groups.
Custom standing profile roles are limited to read-only permissions; built-in roles that administer
access are rejected by resolved ID and permissions. Noncanonical scopes are rejected.

The tool does not assess every privilege conveyed through an ordinary group or provide transactional
rollback. Follow the remaining review findings; offline success does not establish production readiness.


## Export a user's PIM eligibility

Export is read-only in Azure and Graph. It writes a new data-only PSD1 profile into the
bound tenant's private `profiles/` directory. It requires a source account and a new profile
filename key, but no target account and no `-Apply`. Existing files are never overwritten.

```powershell
# Default: direct Azure-resource eligibility, without a Graph PowerShell connection.
.\scripts\cadm\Invoke-CadmAccess.ps1 -Mode export -SourceUser source-admin@example.com -ProfileName peer-azure-jit -ConnectGraph:$false

# Optional: include group and Entra-role eligibility once Graph read access is approved.
.\scripts\cadm\Invoke-CadmAccess.ps1 -Mode export -SourceUser source-admin@example.com -ProfileName peer-all-jit -ExportPlanes AzureResource,Group,DirectoryRole

# Review the generated file, then preview using the existing profile workflow.
.\scripts\cadm\Invoke-CadmAccess.ps1 -Mode profile -ProfileName peer-azure-jit -TargetUser target-admin@example.com -ConnectGraph:$false
```

Azure discovery covers subscriptions visible to the signed-in operator and scopes returned through
those subscriptions, including inherited management-group entries. Duplicate copies of the same
eligibility are collapsed; differing schedules for the same role and scope require manual review.
This is not an inventory of every effective permission. Group-based effective access, active
assignments, and standing roles are not converted into direct eligibility. The exported `Export`
metadata records tenant, source account, scan time, requested planes, and scanned subscription IDs.
These files contain identity/access information and belong in private tenant folders.

By default, finite source expiry dates are preserved as `EndDateTime` in UTC. Future start dates
are retained. A source with permanent eligibility becomes a bounded assignment using the tenant's
`DefaultEligibilityDuration`; it is never exported as permanent eligibility. To deliberately use a
fresh term instead, pass `-EligibilityDuration P90D`. The original finite end date remains recorded
as `SourceEndDateTime`. Profiles with a past expiry must be reviewed before reuse.

Exports fail without saving a profile if any requested read fails, paging is incomplete, source
data is malformed, or an Azure assignment has conditions. Empty selected coverage also produces
no file. Graph exports are opt-in and request only read scopes; an existing session still needs
the appropriate consent and caller permissions. Azure-only exports perform account lookup using
Azure CLI's existing directory access but never call `Connect-MgGraph`.

`PimResourceEligibilities` stores canonical role-definition GUIDs and exact ARM scopes. Group
entries use `GroupId` and `AccessId`; directory entries use `RoleDefinitionId` and tenant scope `/`.
Administrative-unit and app-scoped directory roles are refused. The profile engine resolves IDs,
checks tenant/scope ownership, and checks eligibility expiration policies before applying the new
resource plane or exported Graph entries. Explicit terms that exceed policy are rejected.
Existing eligibilities are retained without renewal or expiry reconciliation. The tool still does
not verify activation MFA/approval settings, guarantee transactional rollback, or verify final
provisioning completion. A successful request submission is not proof of completed assignment.

Use the updated launcher and libraries together. Exported profiles require profile engine 1.6.0
or newer; older engines do not understand the new resource eligibility field.

## Privacy

Only synthetic tenant settings and examples are included. Credentials, real tenant inventories,
generated user reports, and prior local history are excluded from this release.
Runtime audit files contain identity and access information; protect them and do not commit them.
Default audit storage is `%LOCALAPPDATA%/PIM-Automation/cadm-clone/<date>/`.

## Offline validation

```powershell
python -m pip install -r requirements-dev.txt
python -B -m pytest -q -p no:cacheprovider tests/identity
pwsh -NoProfile -File tests/identity/Invoke-ReviewProbes.ps1
powershell -NoProfile -File tests/identity/Invoke-ReviewProbes.ps1
pwsh -NoProfile -File tests/identity/Invoke-P1SafetyTests.ps1
powershell -NoProfile -File tests/identity/Invoke-P1SafetyTests.ps1
pwsh -NoProfile -File tests/identity/Invoke-ExportTests.ps1
powershell -NoProfile -File tests/identity/Invoke-ExportTests.ps1
```

The 95 Python tests inspect source text. Behavioral P1 tests exercise the real planning/write
boundaries and clone entry point with mocked transports. Historical review probes now show both
blocked paths and remaining P2 issues; their saved JSON files are the original pre-fix evidence.
The export suite covers PSD1 round trips, all three eligibility planes, expiry, conditional/partial reads, policy changes, and mocked eligibility requests. No live grants are exercised. Live provisioning remains unverified.

See the [operator runbook](handoff/copy-cadm-access.md), [review](handoff/project-review.md),
and [changelog](CHANGELOG.md).
