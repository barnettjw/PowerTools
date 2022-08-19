function Get-UPSPackageStatus() {
    # Get tracking for UPS packages

    param($Tracking)

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $uri = 'https://www.ups.com/track/api/Track/GetStatus'
    $body = $(@{'TrackingNumber' = @($Tracking) } | ConvertTo-Json)

    $Results = Invoke-RestMethod -Uri $uri -Method Post -ContentType 'Application/Json' -Body $body
    $Results.trackDetails.shipmentProgressActivities | 
    Select-Object date, time, location, activityscan
}