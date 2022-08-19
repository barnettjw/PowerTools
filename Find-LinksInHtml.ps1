function Find-LinksInHtml() {
    # Extract links from HTML source

    param($source)

    Function Get-RedirectedUrl {
        # Check redirects until you find the final destination

        Param ($url)
 
        try {
            $request = [System.Net.WebRequest]::Create($url)
            $request.AllowAutoRedirect = $false
            $response = $request.GetResponse()
 
            if ($response.StatusCode -eq 'Found') { $response.GetResponseHeader('Location') }
            else { $url }
        }
        catch { Write-Warning $_ }
    }

    # setup html object
    Add-Type -AssemblyName 'Microsoft.mshtml'
    $html = New-Object -ComObject 'HTMLFile'
    $html.IHTMLDocument2_write($source)
    
    # filter http/https links and parse out hostname, url, text
    $($html.links | 
        Where-Object { ($_.protocol -eq 'http:') -or ($_.protocol -eq 'https:') } | 
        ForEach-Object {
            $url1 = $(Get-RedirectedUrl $_.href)
            $url2 = $($url1 -split ('://') )[1]
            $_ | Add-Member -MemberType NoteProperty -Name 'url' -Value $(($url2.split('?'))[0])
            $_
        }) | Select-Object textcontent, hostname, url
}