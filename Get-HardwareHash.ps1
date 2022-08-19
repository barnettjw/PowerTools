function Get-HardwareHash() {
    # uses WMI to get the properties needed register a device with Windows Autopilot
    
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Warning 'Script must be Run as Administrator.'
    }
    else {
        # get serial, product key and hardware id (aka 4k hash)
        $session = New-CimSession
        $regKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DefaultProductKey\'
        $serial = (Get-CimInstance -CimSession $session -Class Win32_BIOS).SerialNumber
        $productId = Get-ItemPropertyValue -Name 'ProductId' -Path $regKeyPath
        $hash = (Get-CimInstance -CimSession $session -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData
        Remove-CimSession $session

        # populate data into object
        $object = [pscustomobject]@{
            'Device Serial Number' = $serial
            'Windows Product ID'   = $productId
            'Hardware Hash'        = $hash
        }
    
        try {
            # work around issue that PSScriptRoot isn't available with "run selection"
            if ($profile -match 'VScode') {
                $PathToScript = Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
            }
            elseif ($psISE) { 
                $PathToScript = Split-Path $psISE.CurrentFile.FullPath 
            }
            else { $PathToScript = $PSScriptRoot }
            
            $csv = "$PathToScript\$model-$serial.csv"

            # write data to csv, removing quotes per autopilot requirements
            $object | ConvertTo-Csv -NoTypeInformation | 
            ForEach-Object { $_ -replace '"', '' } | Out-File $csv
            Write-Output "Wrote CSV file to $csv"
        }
        catch { Write-Warning $_ }
    }
}