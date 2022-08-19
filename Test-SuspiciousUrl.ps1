function Test-SuspiciousUrl() {
    # test suspcious url using the ipqualityscore.com API
    # requires free API key

    param(
        $url,
        $apiKey,
        $riskThreshold = 60,
        [switch]$quiet
    )

    [Net.ServicePointManager]::SecurityProtocol = 'Tls12, Tls11'
    $baseURL = 'https://ipqualityscore.com/api/json/url'

    try {
        Add-Type -AssemblyName System.Web
        $encodedUrl = [System.Web.HttpUtility]::UrlEncode($url) 
        $response = Invoke-WebRequest -UseBasicParsing -Uri "$baseURL/$apiKey/$encodedUrl" | 
        ConvertFrom-Json

        # if api call suceeded
        if ($response.success -eq $true ) {
            # get page status: offline, malicious, suspcious or safe
            if (
                ($response.status_code -eq 404) -or `
                ($response.status_code -eq 500) -or `
                ($response.status_code -eq 503)
            ) { $results = 'Offline' }

            elseif (
                $response.spamming -or `
                    $response.malware -or `
                    $response.phishing
            ) { $results = 'Malicious' }

            elseif ($response.risk_score -gt $riskThreshold) {
                $results = 'Suspicious'
            }

            else { $results = 'Safe' }
        
            # return $true if using -quiet and "Safe"
            # otherwise return the entire object
            if ($quiet) { $results -eq 'Safe' }
            else { $response }
        }
        
        # otherwise, return api error message
        else { $response.message }
    }
    catch { Write-Warning $_ }
}