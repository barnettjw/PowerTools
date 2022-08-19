function Measure-DistanceToIP(){
    # calculates the distance to an IP
    
    # calculates the distance "as the crow flies" between the client computer and a given IP
    # supports both miles and kilometers

    param($ip, $uri = 'http://ip-api.com/json', [switch]$kilometers)

    Add-Type -AssemblyName System.Device
    $metersInMile = 1609
    
    $srcJSON = Invoke-WebRequest $uri/$server | ConvertFrom-Json
    $dstJSON = Invoke-WebRequest $uri | ConvertFrom-Json
    $source  = New-Object System.Device.Location.GeoCoordinate $($srcJSON).lat, $($srcJSON).lon
    $dest    = New-Object System.Device.Location.GeoCoordinate $($dstJSON).lat, $($dstJSON).lon
    
    $km = [math]::round($($source.GetDistanceTo($dest) / 1000),0)
    $mi = [math]::round($($source.GetDistanceTo($dest) / $metersInMile),0)

    if($kilometers){ [string]$km + "km" }
    else { [string]$mi + "mi" }
}