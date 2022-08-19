# Required Helper Functions: Get-RandomSymbol, Get-RandomSeed

Function New-RandomPasspharse() {
    param(
        $maxLength = 32,
        $minLength = 15,
        $numberOfWords = 3,
        $symbol = $(Get-RandomSymbol),
        [switch]$number,
        [switch]$verbose
    )

    # get random passphase, with uppercased words seperated by a random symbol ending with a digit
    $password = ((
            $wordlist | Get-Random -Count $numberOfWords -SetSeed $( Get-RandomSeed ) | 
            ForEach-Object { 
                $_.word.substring(0, 1).toupper() + $_.word.substring(1) 
            }
        ) -join $symbol)

    # check if the passpharse is the correct length
    $length = $($password.length)
    if (($length -le ($maxLength - 1)) -and ($length -ge $minLength)) {
        # check if a number needs to be added to meet complexity requirements
        if ($number) { $password + $(Get-Random -Minimum 0 -Maximum 10) }
        else { $password }
    }
    # re-generate invalid passpharse
    else {
        if ($verbose) {
            "************$password************"
            "$length is not between $minLength and $maxLength"
        }
        
        if ($number) { New-RandomPasspharse `
            -numberOfWords $(Get-Random -Minimum 3 -Maximum 11) `
            -symbol $symbol -maxLength $maxLength -minLength $minLength -number
        }
        else {
            New-RandomPasspharse `
            -numberOfWords $(Get-Random -Minimum 3 -Maximum 11) `
            -symbol $symbol -maxLength $maxLength -minLength $minLength
        }
    }
}
