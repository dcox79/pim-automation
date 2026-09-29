# PIM Automation — templates and cloning

PowerShell tools to preview and grant access from reusable tenant profiles or an existing user's assignments.
This is the full provisioning project. The separate [PIM Eligibility Checker](https://github.com/dcox79/pim-eligibility-checker) only inspects eligibility.

**Preview release — known access-safety gaps remain.** Read the [project review](handoff/project-review.md) before using `-Apply`.
Offline tests do not establish safe live provisioning. Interactive clone mode implicitly enables writes.

## Included

- Tenant-specific, data-only PowerShell profile templates.
- Profile planning and apply for standing Azure RBAC, cloud group membership, PIM group eligibility, and Entra directory-role eligibility.
- Automatic and interactive cloning, including Azure-resource eligibility discovery/copying.
- Four synthetic example profiles: Reader, Azure Owner JIT, Microsoft 365 admin JIT, and Global Administrator JIT.
- Operator runbook, known-issue review, static tests, and mocked review probes.

Profiles do not support direct Azure-resource eligibility assignments; clone mode does not copy directory-role eligibility.
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
.\scripts\Copy-CadmAccess.ps1 -SourceUser source-admin@example.com -TargetUser target-admin@example.com
```

Normal profile/clone commands preview by default. After reviewing the plan and known issues,
`-Apply` enables grants and normally requires typing `APPLY`. `-Force` bypasses that confirmation.
Interactive mode enables apply implicitly. Apply is additive and does not roll back partial grants.

The launcher checks the Azure CLI tenant against configuration, but Graph/Azure tenant isolation
is incomplete. The direct clone entry point bypasses launcher binding. Verify both sessions and
resolved identities before applying. Read failures, RBAC condition handling, template restrictions,
and PIM membership handling also have documented gaps.

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
```

The 95 Python tests inspect source text. The 11 mocked review probes reproduce known gaps;
they are not passing safety checks. No live grants are exercised. Live provisioning remains unverified.

See the [operator runbook](handoff/copy-cadm-access.md), [review](handoff/project-review.md),
and [changelog](CHANGELOG.md).
