<#
.SYNOPSIS
Generates a strong, random password based on specified criteria. This function is designed to enhance security for user accounts, encrypted files, and other sensitive data by creating complex passwords that include a mix of lowercase letters, uppercase letters, numbers, and symbols as per user requirements.

.DESCRIPTION
The Get-Password function utilizes a cryptographically secure random number generator to produce passwords that are hard to predict and crack. It allows the user to specify the length of the password and whether to include numeric and/or special characters. This flexibility ensures that the generated passwords meet various security policies and personal preferences.

.PARAMETERS
- Length [int]: Specifies the desired length of the password. The default length is 12 characters. It's recommended to use passwords that are at least 8 characters long for security reasons.
- IncludeSymbols [switch]: When used, the password will include special characters (e.g., !, @, #, $, %, &, *).
- IncludeNumbers [switch]: When used, the password will include numeric characters (0-9).

.EXAMPLE
Get-Password -Length 12 -IncludeSymbols -IncludeNumbers
Generates a 12-character password that includes both symbols and numbers.

.EXAMPLE
Get-Password -Length 16 -IncludeNumbers
Generates a 16-character password that includes numbers but no symbols, using both uppercase and lowercase letters.

.NOTES
It's important to consider the balance between password complexity and memorability. While complex passwords are more secure against brute-force attacks, they might be more challenging to remember. Using a password manager can help manage complex passwords securely.

#>

function Get-Password {
    param (
        [int]$Length = 12,
        [switch]$IncludeSymbols,
        [switch]$IncludeNumbers
    )

    Add-Type -AssemblyName System.Security

    # Define character sets
    $lowerCase = "abcdefghijkmnopqrstuvwxyz"
    $upperCase = $lowerCase.ToUpper()
    $numbers = "0123456789"
    $specialChars = "!@#$%&*?"

    # Initialize the character set based on parameters
    $charSet = $lowerCase + $upperCase
    if ($IncludeNumbers) {
        $charSet += $numbers
    }
    if ($IncludeSymbols) {
        $charSet += $specialChars
    }

    # Ensure the length is within a reasonable range
    if ($Length -lt 8 -or $Length -gt 512) {
        Write-Error "Password length must be between 8 and 512."
        return
    }

    # Generate the password
    $byteArray = New-Object byte[] $Length
    $random = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $random.GetBytes($byteArray)
    $password = $byteArray | ForEach-Object {
        $charSet[$_ % $charSet.Length]
    }

    # Output the password
    -join $password
}