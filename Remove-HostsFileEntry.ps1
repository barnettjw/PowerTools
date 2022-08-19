function Remove-HostsFileEntry() {
    # remove entries in the local HOSTS file in Windows
    param(
        [string]$hostname, 
        [string]$hostfile = "$env:windir\System32\drivers\etc\hosts"
    )

    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Warning 'Script must be Run as Administrator.'
    }
    else {
        $content = Get-Content -Path $hostfile

        # Create empty array for existing content
        $newLines = @()
	
        # Loop through each line in hosts file 
        # and determine if something needs to be kept
        foreach ($line in $content) {
            if ($line -match '^#') {
                # Add all lines that begin with # back to array
                $newLines += $line
            }
            else {
                $line = $line -replace '\s+', "`t"
                $bits = [regex]::Split($line, '\t+')
                if ($bits.count -eq 3) {
                    # Add all existing lines except for the hostname we are removing
                    if ($bits[2] -ne $hostname) { $newLines += $line }
                }
            }
        }
    
        # Clearing the content of the hosts file
        Write-Verbose -Verbose -Message 'Clearing content of HOSTS file'
        try { Clear-Content $hostfile }
        catch {
            Write-Warning -Verbose -Message 'Failed to clear the content of the HOSTS file'
        }
    
        # Add back entries which is not being removed
        foreach ($line in $newLines) {
            Write-Verbose -Verbose -Message "Adding back each entry which is not being removed: $line"
            $line | Out-File -Encoding ASCII -Append $hostfile
        }
    }
}
