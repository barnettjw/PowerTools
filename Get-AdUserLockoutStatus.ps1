function Get-AdUserLockoutStatus() {
    # get the AD user lockout status on everyone domain controller in a domain
    # requires ActiveDirectory module, available from the RSAT feature

    param(
        $user,
        $properties = ('badpwdcount', 'lockedout', 'samaccountname', 
            'LastBadPasswordAttempt', 'msDS-UserPasswordExpiryTimeComputed')
    )

    # get user's lock out status from each Domain Controllers
    $i = 0
    $arr = @()
    $DCs = Get-ADDomainController -Filter * | Sort-Object site, name
    $DCs | ForEach-Object {
        Write-Progress 'Checking lockout status...' "User: $user" `
            -CurrentOperation "Domain Controller: $($_.name)" `
            -PercentComplete (($i / ($DCs.count)) * 100)
        
        Try {
            $adUserStatus = Get-ADUser $user -Properties $properties -Server $_.name | 
            Select-Object $properties
            $passwordExpiryTime = [datetime]::FromFileTime($adUserStatus.'msDS-UserPasswordExpiryTimeComputed')
            $adUserStatus | 
            Add-Member -MemberType NoteProperty `
                -Name 'PasswordExpirationDate' -Value $passwordExpiryTime -Force
            $adUserStatus | 
            Add-Member -MemberType NoteProperty -Name Server -Value $($_.name) -Force
        }
        catch { Write-Warning "Unable to contact ($_.name)" }
        
        $arr += $adUserStatus
        $i++
    }
    
    $arr 
}