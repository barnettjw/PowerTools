function Expand-Url() {
    # expand shortened urls

    param($url, [switch]$quiet = $false)

    try {
        $result = (Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore).Headers.Location
    }
    catch { Write-Warning $_.exception }
    
    # recursively check for redirects
    if ($null -ne $result) {
        if ($quiet) { Expand-Url -url $result -quiet }
        else {
            $result # if not using -quiet, output intermediate redirects
            Expand-Url -url $result 
        }
    }
    else {
        if (-not $quiet) { "Final URL: $url" }
        else { $url }
    }
}