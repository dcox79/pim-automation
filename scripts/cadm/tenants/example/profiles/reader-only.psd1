# Reader only - estate-wide visibility, zero write access, nothing to activate.
# For auditors, new starters awaiting a role decision, and anyone who needs the portal to make
# sense without being able to change anything.
@{
    Name        = 'Reader Only'
    Description = 'Standing Reader at the root MG; no write access, no PIM eligibilities'

    Rbac = @(
        @{ Role = 'Reader'; Scope = 'root-mg' }
    )

    GroupMemberships      = @()
    PimGroupEligibilities = @()
}
