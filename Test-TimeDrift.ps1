function Test-TimeDrift() {
    # diff time between local host and an ntp server

    param(
        $ntpServer = 'pool.ntp.org',
        $acceptableDrift = 30, # acceptable drift in seconds
        [switch]$verbose
    )

    $output = $((w32tm /stripchart /computer:$ntpServer /samples:5 /dataonly) -split ("`n"))[-1]
    $secondsOfDrift = $($output -replace '[^0-9/\:\.\s]' -split (' '))[1]

    if ($verbose) {
        $lastSyncTime = [datetime](
            $(Invoke-Expression 'w32tm /query /status' | 
                Select-String 'sync time').ToString().Split(' ')[-3..-1] -join (' ') | 
            Out-String)

        "Seconds of Drift: $([math]::Round($secondsOfDrift,2))"
        "Current Time: $(Get-Date)"
        "Last Time Sync: $lastSyncTime"
    }
    else {
        try {
            [math]::Round($secondsOfDrift, 2) -lt $acceptableDrift
        }
        catch { }
    }
}