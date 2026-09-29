# M365 workload admin (JIT) - per policy, every M365 admin EXCEPT Global Administrators works
# through PIM for Groups. No standing admin access of any kind.
#
# EXAMPLE ONLY - EDIT THE LIST. These group names are placeholders, not an inventory.
# Select the minimum workload groups needed. Review Global Administrator separately using
# the directory-role profile and its activation policy.
@{
    Name        = 'M365 Workload Admin (JIT)'
    Description = 'Standing Reader at the root MG; M365 admin roles only via PIM-for-Groups activation'

    Rbac = @(
        @{ Role = 'Reader'; Scope = 'root-mg' }
    )

    GroupMemberships = @()

    PimGroupEligibilities = @(
        @{ Group = 'EXAMPLE_PIM_Teams_Admin_Role'; AccessId = 'member' }
        @{ Group = 'EXAMPLE_PIM_Purview_Information_Protection_Admin_Role'; AccessId = 'member' }
        @{ Group = 'EXAMPLE_PIM_Purview_Organization_Management_Role'; AccessId = 'member' }
    )
}
