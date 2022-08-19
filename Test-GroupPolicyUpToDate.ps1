function Test-GroupPolicyUpToDate() {
    # calculate last time gpo's were applied using gpo history in the registry

    param(
        $groupPolicyRefreshTime = 90,
        $groupPolicyRefreshTimeOffset = 30,
        [switch]$quiet,
        [switch]$user
    )

    # get regkey for either computer or user group policies
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    if ($user) { $key = $sid }
    else { $key = 'machine' }
    $gpoRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\
    State\$key\Extension-List\{00000000-0000-0000-0000-000000000000}"
    
    # get timestamp from Group Policy history
    $loTime = Get-ItemProperty -Path $gpoRegPath -Name 'EndTimeLo'
    $hiTime = Get-ItemProperty -Path $gpoRegPath -Name 'EndTimeHi'
    [string]$timestamp = ([long]$hiTime.EndTimeHi -shl 32) + [long] $loTime.EndTimeLo
    
    # get elapsed time since last group policy update 
    $lastUpdate = [DateTime]::FromFileTime($timestamp)
    $elapasedTime = New-TimeSpan -Start $lastUpdate -End $(Get-Date)

    # check if computer has received policy update within refresh interval
    if ($quiet) {
        if (
            $elapasedTime.TotalMinutes -le `
            ($groupPolicyRefreshTime + $groupPolicyRefreshTimeOffset) * 2) 
        { $true }
        else { $false }
    }
    else { $lastUpdate }
}