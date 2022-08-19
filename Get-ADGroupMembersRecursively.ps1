function Get-ADGroupMembersRecursively() {
    <# get AD group members recursively
    (e.g. all members including members in nest groups)
    requires ActiveDirectory module, available from the RSAT feature #>

    param($group)

    $groupsChecked = @()
    Write-Progress -Activity "Users: $($users.Count) Groups Traversed: $($groupsChecked.count)"
    $properties = 'givenname', 'sn', 'mail', 'samaccountname', 
    'extensionattribute14', 'extensionattribute12'

    # get members of current group
    try {
        $members = $(Get-ADGroup $group -Properties members -Server $dc -ErrorAction Continue).members
        $groupsChecked += $group # add current group to groupsChecked array

        # add direct members of current group to users array, if not already present
        try {
            $members | ForEach-Object {
                Get-ADObject $_ -Server $dc -Properties $properties -ErrorAction Continue | 
                Where-Object { $_.objectclass -eq 'user' } } | 
            ForEach-Object {
                if ($script:users.samaccountname -notcontains $_.samaccountname) {
                    $script:users += $_ | Select-Object $properties
                }
            }
        }
        catch { Write-Warning $_ }

        # for nested groups in current group, recursively get group members
        # if group is not already present in groupsChecked array
        $members | ForEach-Object { Get-ADObject $_ -Server $dc -ErrorAction Continue | 
            Where-Object { $_.objectclass -eq 'group' } } | 
        ForEach-Object {
            if ($groupsChecked -notcontains $_.name) {
                Get-ADGroupMembersRecursively -group $_.name -groupsChecked $groupsChecked
            }
        }
    }
    catch { "unable to get $group" }
}
