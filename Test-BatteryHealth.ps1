Function Test-BatteryHealth() {
    # calculate a windows laptop's battery's remaining life span using wmi

    $class = Get-WmiObject -Class 'BatteryStaticData' -List -Namespace 'ROOT\WMI'
    $classExists = $null -ne $class

    if ($classExists) {
        $fullChargeCapacity = (Get-WmiObject -Class 'BatteryFullChargedCapacity' -Namespace 'ROOT\WMI').FullChargedCapacity 
        $designedCapacity = (Get-WmiObject -Class 'BatteryStaticData' -Namespace 'ROOT\WMI').DesignedCapacity 
 
        if ($fullChargeCapacity -eq $designedCapacity) { 
            Write-Host 'Unable to cacluclate battery health' 
        } 
 
        $batteryHealth = ($fullChargeCapacity / $designedCapacity)
        if ($batteryHealth -gt 1) { $batteryHealth = 1.0 } 
        return '{0:P0}' -f $batteryealth
    }
    else { Write-Host 'No battery found' }
}