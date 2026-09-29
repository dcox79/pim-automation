# SYNTHETIC EXAMPLE ONLY. Replace the zero GUID and sample group names before use.
# Keep real tenant bindings private; only this example belongs in a public distribution.
# Example tenant bindings for the CADM access tooling.
#
# One folder per tenant under scripts/cadm/tenants/. The launcher matches the CURRENT az login's
# tenantId against these files and refuses to run when nothing matches - profiles from one
# customer can never be applied inside another's tenant by accident. Everything tenant-specific
# (IDs, group names, scope shorthands) lives here; the scripts stay generic.
#
# PSD1 on purpose: comments work, Import-PowerShellDataFile parses it on 5.1 and 7.x with no
# dependencies, and it is data-only - a tampered file cannot execute code.
@{
    Name     = 'Example Tenant'
    # Entra tenant id. Matched (case-insensitively) against `az account show`.
    TenantId = '00000000-0000-0000-0000-000000000000'
    # Root management group. In Azure the Tenant Root Group's id equals the tenant id, but it is
    # kept as its own key because profiles reference it as a scope and the equality is a detail.
    RootManagementGroupId = '00000000-0000-0000-0000-000000000000'

    # Scope shorthands profiles may use in their Rbac entries. Full '/subscriptions/...' or
    # '/providers/...' scopes are also accepted verbatim; '/' (root scope) never is.
    ScopeTokens = @{
        'root-mg' = '/providers/Microsoft.Management/managementGroups/00000000-0000-0000-0000-000000000000'
    }

    # Stamped into PIM eligibility requests created by profile applies.
    JustificationPrefix = 'CADM provisioning (profile)'

    # Default term for a PIM-for-Groups eligibility, ISO-8601. Eligibilities are never granted
    # permanently: a bounded one lapses if nobody renews it, which is the safer failure, and many
    # PIM policies refuse permanent assignment outright. Clamped down automatically where a
    # group's own policy sets a lower ceiling; a profile may pin its own term per eligibility.
    DefaultEligibilityDuration = 'P365D'
}
