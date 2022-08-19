function Get-Whois() {
    # get whois information via www.whoisxml API
    # Requires: Free API Key

    param(
        $apiKey,
        $domainName,
        $baseUri = 'https://www.whoisxmlapi.com/whoisserver/WhoisService',
        $output = 'JSON',
        $properties = ('domainName', 'createdDate', 'updatedDate', 'expiresDate', 
            'registrarName', 'contactEmail', 'estimatedDomainAge'),
        [switch]$registrant,
        [switch]$nameServers
    )

    $uri = "$($baseUri)?apiKey=$($apiKey)&domainName=$($domainName)&outputFormat=$($output)"
    if ($registrant) { $properties += 'registrant' }
    if ($nameServers) { 
        $properties += @{ n = 'nameServers'; e = { $($_.nameServers.hostNames) } } 
    
    }
    $response = Invoke-RestMethod -Method Get -Uri $uri
    $response.WhoisRecord | Select-Object $properties
}
