# PIM access automation — operator runbook

**Status:** read [the project review](project-review.md) before applying access. The current
engine has confirmed safety gaps. This runbook describes its behavior, not a production approval.

## Configure a tenant

`scripts/cadm/tenants/example/` is synthetic: its tenant ID is all zeros and its group names
start with `EXAMPLE_`. Copy it to a private tenant folder and supply your own approved tenant ID,
management-group scope and group mappings. Real tenant folders are excluded by `.gitignore`.
Keep a controlled private copy outside a public distribution.

The launcher matches the current Azure CLI tenant to `tenant.psd1`. This is only a partial guard:
it does not yet verify that Graph uses the same tenant or restrict every subscription to it.
The direct clone entry point does not enforce this binding.

Prerequisites: PowerShell 5.1 or 7, Azure CLI, an existing authorized `az login`, and
`Microsoft.Graph.Authentication`. Graph requires appropriate consent and caller permissions
for each operation. Read access does not imply write access. Do not use emergency accounts
as the routine provisioning identity.

## Preview

From the project root:

```powershell
.\scripts\cadm\Invoke-CadmAccess.ps1 -ListProfiles
.\scripts\cadm\Invoke-CadmAccess.ps1 -Mode profile -ProfileName reader-only -TargetUser target-admin@example.com
.\scripts\Copy-CadmAccess.ps1 -SourceUser source-admin@example.com -TargetUser target-admin@example.com
```

These examples use synthetic accounts. The source and target must already exist; this tool
assigns access, not user accounts. Prefer explicit object IDs or exact UPNs. The current resolver
can fall back to prefix matching, so verify the resolved target before proceeding.

The launcher without arguments offers clone, interactive clone, profile apply and profile listing.
Normal clone/profile modes preview by default. **Interactive mode implicitly enables apply** and
includes root-scope and active-to-eligible candidates; `all` includes those candidates.

## Profile format

```powershell
@{
    Name = 'Example reader'
    Description = 'Approved Reader scope only'
    Rbac = @( @{ Role = 'Reader'; Scope = 'root-mg' } )
    GroupMemberships = @()
    PimGroupEligibilities = @()
    DirectoryRoleEligibilities = @()
}
```

| Profile key | Current behavior |
|---|---|
| `Rbac` | Standing Azure RBAC |
| `GroupMemberships` | Standing cloud group membership |
| `PimGroupEligibilities` | Eligible group member/owner assignments |
| `DirectoryRoleEligibilities` | Eligible Entra roles at tenant scope |

Profiles do not currently support direct Azure-resource PIM eligibilities. Clone mode does
not currently copy directory-role eligibilities. Group memberships may convey additional
privilege; a group name or `isAssignableToRole` flag does not fully describe that access.

Example profiles: `reader-only`, `azure-owner-jit`, `m365-admin-jit`, `global-admin-jit`.
All require tenant-specific review. Global Administrator eligibility is especially sensitive:
approval, MFA/authentication context and activation duration come from the role's PIM policy.
The current engine does not verify those safeguards before granting eligibility.

Group and directory eligibility default to a bounded term. Policy-aware clamping exists, but
explicit group durations and mirrored end dates bypass it. Azure-resource clones may retain
permanent eligibility if the source has no expiry. Preview output is not a guarantee that the
server will accept the eventual request.

## Read the plan

| Action | Meaning |
|---|---|
| `CREATE` | Candidate new grant; read failures can incorrectly produce this in some paths |
| `SKIP-EXISTS` | Matching assignment found; not a complete duration/condition comparison |
| `SKIP-PIM-ACTIVATED` | Temporary source elevation. **Never grant this** as standing access |
| `SKIP-PIM-MANAGED` | Source eligibility is handled through the PIM group plan |
| `BLOCKED-PIM-ACTIVE` | Active-only group assignment; not copied by default |
| `BLOCKED-PIM-UNKNOWN` | Relevant access state could not be determined |
| `BLOCKED-ONPREM` | Group is mastered in Active Directory |
| `EXCLUDED-ROOT` | Root scope excluded unless explicitly included |
| `INFO-VIA-GROUP` | RBAC conveyed by group membership rather than a direct user assignment |

Check tenant, resolved source/target, scope, standing-versus-eligible status and scan coverage.
`pimGroupsReadable` is diagnostic; the review identifies cases where it can be true despite an
incomplete active-assignment read. A plan with unreadable or missing coverage does not prove parity.

## Apply behavior

`-Apply` enables writes and normally requires typing `APPLY`. `-Force` skips that confirmation;
it is not a separate approval system. `-IncludePimActive` converts selected active-only group
access into eligibility, rather than faithfully copying the source assignment.

Apply is additive. It does not revoke excess access or transactionally roll back partial success.
Existing-assignment checks reduce duplicate work but do not guarantee idempotency for all failure,
pending-request or concurrent-run cases. The report lists the required corrections.

Synced groups produce `ad-actions-<target>-<stamp>.ps1`. The generated commands currently use
display names and assumed AD account names; review and resolve immutable identities before use.
Do not execute those exports blindly.

## Authentication and results

`-UseDeviceCode` selects device-code login. `-ConnectGraph:$false` disables automatic sign-in;
it does not provide an unattended identity. Existing sessions can be stale or belong to a different
tenant. Current scope-request defects are documented in the review.

`-SkipPimRoleCheck` on the direct clone script relaxes its role preflight, not Graph authorization.
Use it only when the caller's actual authority is understood. The launcher does not expose every
clone-script option.

Audit files default to `%LOCALAPPDATA%/PIM-Automation/cadm-clone/<date>/`; `-OutDir` overrides this.
They contain identities and access details and require controlled storage. Existing logs under
older paths were not migrated or erased. Current JSON records the plan before confirmation and
execution, not verified final outcomes.

Exit codes: 0 generally means preview/completion/cancellation, 1 indicates a failed grant,
2 indicates certain apply refusals. Incomplete discovery may still return success; automation
must not treat exit code 0 alone as verified access parity.

```powershell
Get-Help .\scripts\Copy-CadmAccess.ps1 -Full
python -B -m pytest -q -p no:cacheprovider tests/identity
pwsh -NoProfile -File tests/identity/Invoke-ReviewProbes.ps1
```

The Python suite checks source text. Review probes demonstrate current gaps with synthetic data
and mocked APIs. Neither establishes successful live provisioning.
