function Get-SslGrade() {
    # Get's SSL Grade (A to F) of a https site
    # wrapper around ssllabs.com api

    param($domain, [switch]$quiet, [switch]$verbose)

    $baseApi = 'https://api.ssllabs.com/api/v3'
    $json = Invoke-WebRequest -Uri "$baseApi/analyze?host=$domain"

    try {
        $endpoints = $($json | ConvertFrom-Json).endpoints

        if ($quiet) {
            if ($endpoints.grade -eq 'A+') { return $true }
            else { return $false }
        }

        if ($endpoints.grade -eq 'A+'){
            [pscustomobject]@{
                domain            = $domain
                grade             = $object.grade
                ipaddress         = $object.ipaddress
            }
        }
        else {
            $ip = $endpoints.ipAddress
            $uri = "$baseApi/getEndpointData?host=$domain&s=$ip"
            $object = $(Invoke-WebRequest -Uri $uri).content | ConvertFrom-Json

            [pscustomobject]@{
                domain            = $domain
                grade             = $object.grade
                ipaddress         = $object.ipaddress
                gradeTrustIgnored = $object.gradeTrustIgnored
                protocols         = $object.details.protocols
                rc4               = $object.details.supportsRc4
                statusCode        = $object.details.httpStatusCode
            }
        }

        if ($verbose) {
            $ip = $endpoints.ipAddress
            $uri = "$baseApi/getEndpointData?host=$domain&s=$ip"
            $(Invoke-WebRequest -Uri $uri).content | ConvertFrom-Json | ConvertTo-Json -Depth 5
        }
    }
    catch { Write-Warning $_ }
}