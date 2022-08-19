function Test-DNSConnection() {
    # tests if a dns server for the specified host and zone is accessible

    # -admin checks for rights to get the resource record
    # -admin requires DnsServer module, included in the RSAT feature
    param($hostname, $zonename, [switch]$admin)

    $dnsParam = @(
        Name = $server
        Server = $server
        ErrorAction = Stop
    )

    $rrParam = @(
        Name = $hostname 
        ZoneName = $zonename 
        ComputerName = $server 
        RRType = A
        ErrorAction = Stop
    )

    try {
        $server = "$hostname.$zonename"
        Resolve-DnsName @dnsParam -DnsOnly -QuickTimeout | Out-Null
    
        if ($admin) {
            try { Get-DnsServerResourceRecord @rrParam | Out-Null }
            catch { return $false }
        }
        return $true
    }
    catch { return $false }
}