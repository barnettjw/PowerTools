function Invoke-UrlScreenShot() {
    #Get screenshot using urlscan.io API, option to either download or view image

    param(
        $url, $timeout = 15, 
        [switch]$maxLength, [switch]$view, [switch]$download,
        $path = "$env:USERPROFILE\downloads"
    )

    if ($maxLength) { $height = 10000 }
    else { $height = 2000 }

    $uri = "https://urlscan.io/liveshot/?height=$height&url=$url"

    if ($view) {
        try {
            $response = Invoke-WebRequest -Uri $uri -TimeoutSec $timeout -UseBasicParsing -ErrorAction stop
            $img = [System.Drawing.Image]::FromStream($($response.RawContentStream))
            Out-Image -img $img
        }
        catch { Write-Warning $_ }
    }

    if ($download) {
        $now = Get-Date -UFormat '%Y%m%d%H%M%S'
        $hostname = $([System.Uri]$url).Host
        $filepath = "$path\screenshot-$hostname-$now.png"
        try { 
            Invoke-WebRequest -Uri $uri -OutFile $filepath -TimeoutSec $timeout -UseBasicParsing
            "file downloaded: $filepath"
        }
        catch { Write-Warning $_ }
    }
}