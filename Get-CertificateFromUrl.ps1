# Required Helper Functions: Unblock-InvalidCertificates

function Get-CertificateFromUrl() {
    # get SSL certificate details from a url
    # adapted from: https://amgeneral.wordpress.com/2019/01/03/powershell-download-certificate-chain-from-https-site/

    param($url)

    try {
        Test-NetConnection $([System.Uri]$url).host -ErrorAction Stop | Out-Null
        
        # Allow connections to expired and otherwise invalid certs
        Unblock-InvalidCertificates

        #region - get cert
        $chain = $null
        $cert = $null
        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $WebRequest = [Net.WebRequest]::CreateHttp($url)
        $WebRequest.AllowAutoRedirect = $true
        try {
            $WebRequest.GetResponse() | Out-Null
            $chain.Build($WebRequest.ServicePoint.Certificate.Handle) | Out-Null
            $cert = $chain.ChainElements[0].Certificate
        }
        catch { }
        #endregion

        #region - add additional properties

        # add wildcard property
        if ($cert.Subject -ilike 'CN=`*.*') { $wildcard = $true }
        else { $wildcard = $false } 
        $cert | Add-Member -MemberType NoteProperty -Name 'WildCard' -Value $wildcard -Force

        # add expiration status
        if ($cert | Where-Object { $_.notafter -gt $(Get-Date).AddDays(90) } ) {
            $status = 'Current'
        }
        elseif ($cert | 
            Where-Object { ($_.notafter -le `
                    $(Get-Date).AddDays(90)) -and ($_.notafter -ge $(Get-Date) ) } ) {
            $status = 'Expiring Soon'
        }
        else { $status = 'Expired' }
        $cert | Add-Member -MemberType NoteProperty -Name 'Status' -Value $status -Force
    
        $cert | Add-Member -MemberType NoteProperty -Name Url -Value $url -Force
        #endregion

        $cert | Select-Object URL, Status, Wildcard, DnsNameList, NotAfter, 
        NotBefore, ThumbPrint, Issuer, Subject, EnhancedKeyUsageList
    }
    catch { Write-Warning $_ }
}