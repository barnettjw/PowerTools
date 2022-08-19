function Send-EmailOutlook() {
    # programtically send an email using the Outlook desktop client

    param($to, $subject, $body, [switch]$quiet)

    function Test-Outlook() {
        # Test if outlook is currently running in the current security context

        param($quiet = $false)

        # check if outlook is running
        if ($null -ne (Get-Process 'outlook' -ea SilentlyContinue)) {

            # check if script is running as admin
            $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
            if ($elevated) {
                if (-not $quiet) {
                    Write-Warning 'This script CANNOT be run as admin'
                }
                return $false
            }
            else {
            
                # check if script is running as different user than outlook
                $currentUser = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
                $outlookProcessOwner = $(Get-WmiObject -Class Win32_Process -Filter "name='outlook.exe'" -ErrorAction Stop).GetOwner()
                $outlookProcessOwnerUser = "$($outlookProcessOwner.Domain)\$($outlookProcessOwner.user)"
                
                if ($outlookProcessOwnerUser -eq $currentUser) { return $true }
                else {
                    if (-not $quiet) {
                        Write-Warning "This script must be run as the same user 
                        as $processName ($outlookProcessOwnerUser)"
                    } 
                }
                return $false
            }
        }
        else {
            if (-not $quiet) {
                Write-Warning 'Outlook is not running, unable to send email.'
            }
            return $false
        }
    }

    if (Test-Outlook -quiet $quiet) {
        try {
            $outlook = New-Object -ComObject Outlook.Application
            $mail = $Outlook.CreateItem(0)
    
            $mail.To = $to
            $mail.Subject = $subject
            $mail.HTMLbody = $body
    
            $mail.Send()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Outlook) | Out-Null
            Write-Output 'Email sent.'
        }
        catch { Write-Warning $_ }
    }      
}