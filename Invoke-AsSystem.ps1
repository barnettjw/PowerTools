function Invoke-AsSystem() {
    # downloads psexec and starts a process as SYSTEM
    param($path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_ise.exe")
    
    # self-elevate to local admin rights
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
    }
    else {
        # if not already running as SYSTEM, elevate to SYSTEM using psexec
        if ($(whoami) -ne 'nt authority\system') {       
            Invoke-WebRequest -Uri 'http://live.sysinternals.com/psexec.exe' -OutFile 'psexec.exe'
            Invoke-Expression ".\psexec.exe -accepteula -s -i $path"
            if (Test-Path psexec.exe) { Remove-Item psexec.exe }
        }
    }
}