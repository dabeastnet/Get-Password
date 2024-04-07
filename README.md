# Get-Password

## Introduction
The `Get-Password` PowerShell module provides a simple yet powerful tool for generating strong, random passwords. This module is designed to enhance security for user accounts, encrypted files, and other sensitive data by creating complex passwords. It supports customization options such as password length and the inclusion of numbers and symbols to meet various security policies and preferences.

## Requirements
- PowerShell 5.1 or higher
- Windows 7 or later, or a compatible version of Windows Server

## Installation
No specific installation process is needed. You can integrate the `Get-Password` function into your scripts or PowerShell session by simply copying the function definition.


## Usage

### Basic Password Generation
To generate a simple 12-character password without symbols or numbers:
```powershell
Get-Password -Length 12
```

### Including Numbers and Symbols
To generate a 16-character password that includes numbers and symbols:
```powershell
Get-Password -Length 16 -IncludeNumbers -IncludeSymbols
```

### Parameters
- `-Length [int]`: Specifies the desired length of the password. Default is 12 characters.
- `-IncludeSymbols [switch]`: Include special characters in the password.
- `-IncludeNumbers [switch]`: Include numeric characters in the password.

## Additional Notes
- It's important to strike a balance between password complexity and memorability. While more complex passwords are more secure against brute-force attacks, they can be harder to remember.
- Consider using a password manager to securely store complex passwords.

## Contributing
Contributions to improve `Get-Password` are welcome. Please feel free to submit pull requests or open issues to discuss proposed changes or enhancements.

## License
This project is licensed under the GNU General Public License v3.0 - see the `COPYING` file for more details.