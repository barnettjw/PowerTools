function Test-Snmp() {
    # check if an snmp device is online by getting an oid

    [cmdletbinding()]
    param(
        $ip,
        $community = 'public',
        $oid = '.1.3.6.1.2.1.1.5.0' # sysname
    )

    $checkSnmp = $false

    if (Test-Connection $ip -Quiet) {
        $snmp = New-Object -ComObject olePrn.OleSNMP

        try { 
            $snmp.open($ip, $community, 2, 3000)
            $snmpData = $snmp.get($OID)
            Write-Verbose "`nSNMP Response: $snmpData"
            $checkSnmp = $True
        }
        catch { Write-Warning 'Fail: unable to connect via snmp' }
        if ($checkSnmp) { "Success: Connected to $ip via snmp" }
    }
    else { Write-Warning "Fail: Unable to ping: $ip" }
}