function Get-AWSEndpointLocations() {
    # get the location (city, state, country) that an AWS service is based in
    # supports filtering by service

    param(
        $url = 'https://ip-ranges.amazonaws.com/ip-ranges.json',
        $service
    )

    # get networks
    $networks = $((Invoke-WebRequest $url).content | ConvertFrom-Json).prefixes 
    if ($service) { $networks = $networks | Where-Object { $_.service -match $service } }
    
    #convert IPs into JSON for batch geolocating 
    $IPs = New-Object System.Collections.ArrayList
    $networks | Sort-Object $_.region | ForEach-Object {
        $query = @{}
        $query.Add('query', $(($_.ip_prefix -split ('/'))[0]) )
        $IPs.Add($query) | Out-Null
    }

    # geolocate networks in batches of 100 using ip-api.com
    $results = @()
    $(for ($i = 0; $i -le $($IPs.Count); $i += 100) {
            $batch = $($IPs | Select-Object -Skip $i -First 100 | ConvertTo-Json)
            $uri = 'ip-api.com/batch?fields=country,regionName,city,query,message'
            $results += ((Invoke-WebRequest -Uri $uri -Method Post -Body $batch).content | ConvertFrom-Json)
        })

    $results | Sort-Object Country, RegionName, City
}