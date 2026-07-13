# PasswordForge

PasswordForge is a Windows PowerShell application that rates password strength, identifies weak patterns, creates stronger alternatives, and generates random passwords and passphrases. All analysis runs locally.

## Features

- Password score, rating, entropy estimate, and length analysis
- Common-password, sequence, keyboard-pattern, repetition, and year warnings
- Password policy checklist and practical improvement suggestions
- Stronger-password generation based on the current password
- Cryptographically secure random password generation
- Readable passphrase generation
- Similar-character exclusion
- Copy, clear, show, and dark-mode controls

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or PowerShell 7

## Run

Double-click `RUN_PASSWORDFORGE.bat`, or run:

```powershell
powershell -ExecutionPolicy Bypass -File .\PasswordForge.ps1
```

## Privacy and limitations

PasswordForge does not send or save passwords. Its score and entropy values are local estimates. It does not query breach databases and should not replace unique passwords, multifactor authentication, or a password manager.

## Validation

```powershell
powershell -ExecutionPolicy Bypass -File .	ests\Validate-Project.ps1
```

## License

MIT
