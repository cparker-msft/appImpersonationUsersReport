# appImpersonationUsersReport
Report of M365 3rd party EWS applications using accounts that have the ApplicationImpersonation RBAC role assigned 

## Description
The high-level overview of what this script does is the following:

1. Get the list of accounts with the ApplicationImpersonation RBAC (Role Based Access Control) role via the Get-ManagementRoleAssignement cmdlet
2. For each account returned in Step 1, get its UPN and SID using the Get-User cmdlet
3. Do a Unified Audit Log search over a given time period using the Searc-UnifiedAuditLog cmdlet, filtering on the MailItemsAccessed operation
4. For each SID, review UAL results for events with the SID as LogonUserSid and a different UPN for the MailboxOwnerUPN mailbox
5. Log hits along with the AppId
6. Perform some filtering and deduplication so that we're outputting the impersonation accounts in use by a given App Id, effectively performing the Impersonation account -> Application mapping
   
## Usage
Step 1: Connect to [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps):
``` PowerShell
PS C:\Users\MyUser\Scripts> Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
```
Step 2: Run the script from the local directory in a PowerShell terminal:
``` PowerShell
PS C:\Users\MyUser\Scripts> .\appImpersonationUsersReport.ps1
```

## Disclaimer
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
