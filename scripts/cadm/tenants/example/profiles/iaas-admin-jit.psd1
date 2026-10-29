# Synthetic job template. Select an approved scope binding in a private tenant configuration.
@{
    Name = 'IaaS Admin (JIT)'
    Description = 'Virtual Machine Administrator Login and Contributor eligibility at a configured scope'
    Metadata = @{
        SchemaVersion = '1'
        Version = '1.0.0'
        Owner = 'Example Team'
        Purpose = 'Synthetic infrastructure administration example; review before use'
        Status = 'Draft'
        ReviewDate = '2027-01-29'
        DefaultScopeToken = 'example-mg'
    }
    Rbac = @()
    GroupMemberships = @()
    PimGroupEligibilities = @()
    DirectoryRoleEligibilities = @()
    PimResourceEligibilities = @(
        @{ RoleDefinitionId = '1c0163c0-47e6-4577-8991-ea5c82e286e4'; Scope = 'template-scope' }
        @{ RoleDefinitionId = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; Scope = 'template-scope' }
    )
}
