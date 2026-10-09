# Active Directory PowerShell Tools

A small set of read-only PowerShell scripts for looking up Active Directory users, group memberships, and group members. The scripts use LDAP through .NET's `System.DirectoryServices` and the credentials of the current Windows logon session. They do not require the ActiveDirectory / RSAT PowerShell module.

## Requirements

- Windows with PowerShell 7 or later (`pwsh`). These scripts use Windows-only `System.DirectoryServices` APIs and do not run on Linux or macOS.
- Network connectivity to a domain controller and read access to the requested directory objects.
- Run the commands from an account that can read the target objects.

No elevation or domain-admin rights are required for ordinary read access. Your domain's access controls still apply.

## Scripts

| Script | Purpose |
| --- | --- |
| [Get-ADGroupMembers.ps1](Get-ADGroupMembers.ps1) | Lists direct group members, or nested members with `-Recursive`. |
| [Get-ADUserGroups.ps1](Get-ADUserGroups.ps1) | Lists direct and nested groups for a user, including the primary group. |
| [Get-ADUserDetailsByUsername.ps1](Get-ADUserDetailsByUsername.ps1) | Looks up user display name and account details from a username or input file. |
| [Get-ADUserByName.ps1](Get-ADUserByName.ps1) | Finds users by full or partial name terms. |

## Usage

Open PowerShell 7 in the project directory. If script execution policy prevents running local scripts, use your organization's approved policy or launch a session with an appropriate policy setting.

### List group members

```powershell
.\Get-ADGroupMembers.ps1 -Group 'Finance Readers'
.\Get-ADGroupMembers.ps1 -Group 'finance-readers' -Recursive
```

The group value can be a group's sAMAccountName, common name, name, or distinguished name. If a short name matches multiple groups, use the distinguished name. Recursive results include the nested group objects as well as their members.

### List a user's groups

```powershell
.\Get-ADUserGroups.ps1 -User 'jsmith'
.\Get-ADUserGroups.ps1 -User 'jsmith@example.com' |
    Export-Csv -Path .\groups.csv -NoTypeInformation
```

The user value can be a sAMAccountName, user principal name (UPN), or distinguished name. The output includes a `MembershipType` of `Direct`, `Nested`, or `Primary`.

### Get user details by username

```powershell
.\Get-ADUserDetailsByUsername.ps1 -Username 'jsmith'
.\Get-ADUserDetailsByUsername.ps1 -InputFile .\usernames.txt |
    Where-Object Status -eq 'Found' |
    Select-Object InputValue, Name, Username, UserPrincipalName
```

The input file contains one username per line; blank lines are ignored. Accepted username formats are sAMAccountName, `DOMAIN\username`, and UPN. The output includes `InputValue`, `LineNumber`, `Name`, `Username`, `UserPrincipalName`, `Status`, and `ErrorMessage`.

### Find users by name

```powershell
.\Get-ADUserByName.ps1 -PartialName 'John Smith'
.\Get-ADUserByName.ps1 -InputFile .\names.txt -MaxResults 20 |
    Where-Object Status -eq 'Found' |
    Select-Object InputValue, Name, Username, UserPrincipalName
```

Each input is split into words. Every word must match at least one of the user's display name, name, given name, surname, or sAMAccountName fields. `-MaxResults` sets the per-input return cap (default 50, allowed range 1–1000). `ResultCount` reports the number of rows returned for that input, so it may equal the cap even when more matches exist. The output includes `InputValue`, `LineNumber`, `Name`, `Username`, `UserPrincipalName`, `ResultCount`, `Status`, and `ErrorMessage`.

For either file-based script, create a UTF-8 plain-text file with one input on each line. Both scripts emit objects to the pipeline, so you can filter, select, or export results with standard PowerShell commands.

## Notes

- The scripts search the current domain. They do not accept an alternate domain controller or credentials.
- `NotFound` means no matching user was returned. `Error` indicates an error processing that input; connection and domain setup failures terminate the script with an error.
- Group-membership results are scoped to the current domain. Cross-domain referrals and foreign security principals may not resolve to full object details.
- These scripts only read directory data.

## AI authorship and public-domain dedication

The scripts and documentation in this project were written by an LLM. The project owner dedicates the project to the public domain using [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/), to the fullest extent permitted by law. AI generation by itself does not guarantee that a work is in the public domain in every jurisdiction, and the dedication cannot waive rights held by third parties.

## Disclaimer

Use these scripts entirely at your own risk. They are provided “as is,” without warranties or guarantees of accuracy, availability, security, or fitness for a particular purpose. Review the code and verify its output before relying on it. The project owner and contributors accept no responsibility for loss, damage, or other consequences arising from use, modification, or distribution, to the fullest extent permitted by law.
