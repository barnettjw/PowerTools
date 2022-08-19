# Required Helper Functions: Invoke-TShark

function Get-CDP() {
    # Gets a device's switch port using CDP (Cisco Discovery Protocol)
    # Requires Wireshark

    param(
        $interface,
        $log = "$PathToScript\frame.log"
    )

    # work around issue that PSScriptRoot isn't available with "run selection"
    if ($profile -match 'VScode') {
        $PathToScript = Split-Path $psEditor.GetEditorContext().CurrentFile.Path
    }
    elseif ($psISE) { $PathToScript = Split-Path $psISE.CurrentFile.FullPath }
    else { $PathToScript = $PSScriptRoot }

    # setup tshark capture filter
    $captureFilter = '(ether proto 0x88cc) or ( ether host 01:00:0c:cc:cc:cc and ether[16:4] = 0x0300000C and ether[20:2] == 0x2000)'
    $json = Invoke-TShark -interface $interface -captureFilter $captureFilter | 
    Tee-Object -FilePath $log
    $frame = $($json | ConvertFrom-Json)._source.layers

    # parse out lldp properties
    if ($frame.lldp) {
        $lldp = $frame.lldp | Select-Object -First 1
        $sysNameKey = $($lldp.psobject.Properties | 
            Where-Object { $_.name -ilike 'system Name = *' }).name
        $sysDescKey = $($lldp.psobject.Properties | 
            Where-Object { $_.name -ilike 'System Description = *' }).name
        $switchPort = $($lldp.psobject.Properties |
            Where-Object { $_.name -ilike 'Port Subtype = *' }).name
    
        [pscustomobject]@{
            'Protocol'              = 'LLDP'
            'System Name'           = $lldp.$sysNameKey.'lldp.tlv.system.name'
            'System Description'    = $lldp.$sysDescKey.'lldp.tlv.system.desc'
            'Switch Port'           = $lldp.$switchPort.'lldp.port.id'
            'Management IP Address' = $lldp.'Management Address'.'lldp.mgn.addr.ip4'
            'VLAN ID'               = $lldp.'IEEE - Port VLAN ID'.'lldp.ieee.802_1.port_vlan.id'
        }
    }

    # parse out CDP properties
    if ($frame.cdp) {
        $cdp = $frame.cdp | Select-Object -First 1
        $switchPort = (($cdp | Get-Member -MemberType NoteProperty) | 
            Where-Object { $_.name -ilike 'Port ID: *' }).Name
        $ipKey = (($cdp.Addresses | Get-Member -MemberType NoteProperty) | 
            Where-Object { $_.name -ilike 'ip address: *' }).Name
        $vlanIdKey = (($cdp | Get-Member -MemberType NoteProperty) | 
            Where-Object { $_.name -ilike 'Native VLAN: *' }).Name

        [pscustomobject]@{
            'Protocol'              = 'CDP'
            'Version'               = $cdp.'cdp.version'
            'Switch Port'           = $cdp.$switchPort.'cdp.portid'.Split(' ')[1]
            'Management IP Address' = $cdp.Addresses.$ipKey.'cdp.nrgyz.ip_address'
            'VLAN ID'               = $cdp.$vlanIdKey.'cdp.native_vlan'
        }
    }
}