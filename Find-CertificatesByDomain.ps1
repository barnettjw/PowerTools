function Find-CertificatesByDomain() {
    # find certificates issued for a domain (including subdomains)
    # includes, dns names, issuer, thumbprint, issuer, dates valid
    # uses the Cert Spotter API

    param(
        $domain,
        [switch]$subdomains,
        [switch]$showCert
    )

    $uri = "https://api.certspotter.com/v1/issuances?domain=$domain&expand=dns_names&expand=issuer"
    if ($subdomains) { $uri += '&include_subdomains=true' }
    if ($showCert) { $uri += '&expand=cert' }

    try {
        $results = Invoke-WebRequest -Uri $uri | ConvertFrom-Json
        $results | Select-Object -Property * -ExcludeProperty ('id', 'tbs_sha256')
    }
    catch { Write-Warning $_ }
}