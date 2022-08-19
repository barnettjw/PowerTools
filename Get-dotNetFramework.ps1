Function Get-DotNetFramework() {
    # loop through various keys .Net has used over the years
    
    $versions = @('v4\Client', 'v4\Full', 'v3.5', 'v3.0', 'v2.0.50727', 'v1.1.4322') | 
    ForEach-Object {
        $parenthPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\$($_)"
        
        # loop through each key and get propreties
        Get-ChildItem $parenthPath -ea SilentlyContinue | ForEach-Object {
            $arr = $($_.PsPath).Split('\')
            $regPath = $arr[1..$arr.Count] -join ('\')

            # filter keys
            Get-ItemProperty $regPath | 
            Where-Object { ($null -ne $_.version) -and ($_.install -eq 1) } | 
            
            # select desired properties
            Select-Object @{n = 'Name'; e = { 'Microsoft .Net Framework' } }, 
            Version, Release
        }
    }

    $versions
}
