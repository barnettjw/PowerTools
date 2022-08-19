function Add-HostsFileEntry() {
    # add entries in the local HOSTS file in Windows
    
    [cmdletbinding()]
    param(
        $ip,
        $hostname, 
        $hostfile = "$env:windir\System32\drivers\etc\hosts"
    )

    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Warning 'Script must be Run as Administrator.'
    }
    else {
        $Content = Get-Content -Path $hostfile | Select-String -NotMatch '^#' | 
        Select-String -Pattern ([regex]::Escape("$hostname")) 

        if (-NOT($Content)) {
            #strip out whitespace from end of file
            (Get-Content -Path $hostfile -Raw) -replace '(?s)\s*$' | 
            Set-Content -Path $hostfile -NoNewline

            #write out entry, preceeding with a newline and a tab
            Write-Verbose -Verbose -Message "Adding $ip $hostname to hosts file"
            "`n`t$iP`t" + $hostname | Out-File -Encoding ASCII -Append $hostfile
        }
        else {
            Write-Warning -Verbose -Message "$hostname already exists in the HOSTS file"
        }
    }
}