function Get-LastLogon() {
    # get user's last logon from each domain controller

    param($user = $env:USERNAME)

    Get-ADDomainController -Filter * | ForEach-Object {
        $server = $_.hostname
        
        try {
            Get-ADObject -IncludeDeletedObjects `
            -Filter { samaccountname -eq $user } `
            -Server $server `
            -Properties SamAccountName, LastLogon, DisplayName | 
            Select-Object 'SamAccountName', 
            @{ n = 'LastLogonDate'; e = { [datetime]::FromFileTime($_.lastlogon) } }, 
            'DisplayName', @{ n = 'dc'; e = { $dc } }, 'BadPwdCount', 'LockedOut', 
            'LastBadPasswordAttempt', 'Deleted'
        }
        catch { Write-Warning $_ }
    }
}