# Azure Owner (JIT) - the standard posture for a CADM account that administers Azure.
#
# EXAMPLE ONLY. Map the sample group to an approved group in your own tenant.
# Intended posture: standing Reader, with Owner available through PIM activation. Deliberately NOT expressible here: standing Owner, User Access Administrator, root-scope
# grants, or permanent membership of a PIM-managed group - the engine refuses all four no
# matter what a profile says.
@{
    Name        = 'Azure Owner (JIT)'
    Description = 'Standing Reader at the root MG; Owner only via PIM-for-Groups activation'

    # Standing Azure RBAC. Scope is a token from tenant.psd1 ScopeTokens, or a full
    # '/subscriptions/...' / '/providers/...' resource id.
    Rbac = @(
        @{ Role = 'Reader'; Scope = 'root-mg' }
    )

    # Standing membership of plain cloud groups (NOT PIM-managed, NOT role-assignable -
    # the engine verifies both before granting).
    GroupMemberships = @()

    # PIM-for-Groups eligibilities: the ability to activate, never standing access.
    # AccessId is 'member' or 'owner'. Eligibility has a bounded default term; the PIM policy
    # governs activation (MFA, justification, approval, duration).
    PimGroupEligibilities = @(
        @{ Group = 'EXAMPLE_PIM_Azure_Owner_Role'; AccessId = 'member' }
    )
}
