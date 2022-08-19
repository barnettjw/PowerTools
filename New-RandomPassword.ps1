#Required Helper Functions: Get-RandomSeed

Function New-RandomPassword() {
    # generates password according to password complexity rules

    # to get decimal values of ascii characters
    # see: https://theasciicode.com.ar/

    param(
        $minLength = 15, $maxLength = 30, $symbolsIncl = $true,
        $accentedLettersIncl = $false, $symbolExcl = @(' ', '"', '&', "'", '`'),
        $accentedLettersExcl = @(215, 247)
    )
    
    $length = $(Get-Random -Minimum $minLength -Maximum $maxLength)

    # decimal values of ascii letters and digits
    $asciiDecs = 48..57 + 65..90 + 97..122
    
    if ($symbolsIncl -eq $true) {
        # decimal values of ascii symbols
        $asciiDecs += 32..47 + 58..64 + 91..96 + 123..126
        
        # convert symbols in $symbolExcl to decimal ascii
        # then remove from $asciiDecs array
        $symbolRemove = @()
        $symbolExcl | ForEach-Object { $symbolRemove += [byte][char]$_ }
        $asciiDecs = $asciiDecs | Where-Object { $_ -notin $symbolRemove }
    }

    if ($accentedLettersIncl -eq $true) {
        # Latin-1 accented letters
        # see: https://cs.stanford.edu/people/miles/iso8859.html
        $asciiDecs += 192..255 

        $asciiDecs = $asciiDecs | Where-Object { 
            $_ -notin $accentedLettersExcl 
        }
    }

    <# 
       The array is multiplied by 100 times because,
       PowerShell only selects each value once.
       
       Get-Random selects the specified number of values from array for a seed value,
       it calls Get-RandomSeed each value selected is casted as a char.
       
       Finally all chars are joined as a string
    #>

    ($asciiDecs * 100 | Get-Random -Count $length -SetSeed $(Get-RandomSeed) | 
    ForEach-Object { [char]$_ }) -join ''
}