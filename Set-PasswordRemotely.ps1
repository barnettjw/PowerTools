function Set-Password() {
    # Change an expired password remotely without Interactive access as that user.
    
    # Uses NetUserChangePassword method from the netapi32.dll
    # adapted from: https://gist.github.com/chryzsh/f814a3d6088c5bc8f1adfafce2eb3779

    function Set-PasswordRemotely {
        [CmdletBinding()] param(
            $userName,
            [SecureString] $oldPassword,
            [SecureString] $newPassword
        )

        # Getting a DC in the computer's AD site
        $domainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().name

        # load the netapi32 dll
        $dllImport = '[DllImport("netapi32.dll", CharSet = CharSet.Unicode)] public static extern bool NetUserChangePassword(string domain, string username, string oldpassword, string newpassword);'
        $NetApi32 = Add-Type -MemberDefinition $dllImport -Name 'NetApi32' -Namespace 'Win32' -PassThru
    
        # set a new password using netapi32 NetUserChangePassword method
        if ($result = $NetApi32::NetUserChangePassword($domainController, $userName, $oldPassword, $newPassword)) {
            Write-Output -InputObject 'Password change failed. Please try again.'
        }
        else { Write-Output -InputObject 'Password change succeeded.' }
    }

    Add-Type -AssemblyName Microsoft.VisualBasic
    $username = [Microsoft.VisualBasic.Interaction]::InputBox('username?', ' ')
    $oldPasswordSecure = Read-Host 'Old Password?' -AsSecureString
    $newPasswordSecure = Read-Host 'New Password?' -AsSecureString

    $oldPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($oldPasswordSecure))
    $newPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPasswordSecure))

    Set-PasswordRemotely -userName $username -oldPassword $oldPassword -newPassword $newPassword
}