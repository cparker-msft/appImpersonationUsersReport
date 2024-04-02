<#
.SYNOPSIS
This script helps to identify users with the ApplicationImpersonation RBAC role assignment and help determine which applications are using these accounts.

.DESCRIPTION
The high-level overview of what this script does is the following:

1. Get the list of "ApplicationImpersonation users" via the Get-ManagementRoleAssignement cmdlet
2. For each user returned in Step 1, get their UPN and SID using the Get-User cmdlet
3. Do a Unified Audit Log search over a given time period using the Searc-UnifiedAuditLog cmdlet, filtering on the MailItemsAccessed operation
4. For each SID, review UAL results for events with the SID as LogonUserSid and a different UPN for the MailboxOwnerUPN mailbox
5. Log hits along with the AppId
6. Perform some filtering and deduplication so that we're ultimately outputting the impersonation accounts in use by a given App Id, effectively performing the required Impersonation account -> Application mapping

.EXAMPLE
Step 1: Log in to Exchange Online PowerShell
Step 2: Run the script from the local directory in a PowerShell terminal:
    PS C:\Users\MyUser\Scripts> .\appImpersonationUsersReport.ps1

.NOTES
Reference: https://aka.ms/applicationimpersonationdeprecation 

.AUTHOR
Cameron Parker

.DATE
03/13/2024

.DISCLAIMER
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
#>

#Modify the values for the following variables to configure the audit log search.
$logFile = ".\AuditLogSearchLog.txt"
$outputFile = ".\AuditLogRecords.csv"
$userSidsFile = ".\UserSids.csv"
$filteredResultsFile = ".\FilteredResults.csv"
$impersonationUserMappingFile = ".\impersonationUserMapping.csv"
#[DateTime]$start = [DateTime]::UtcNow.AddDays(-1)
#[DateTime]$end = [DateTime]::UtcNow
[DateTime]$start = "2/13/2024 00:00"
[DateTime]$end = "2/15/2024 00:00"
$operations = "MailItemsAccessed"
$resultSize = 5000
$intervalMinutes = 60


# Start script
Function Write-LogFile ([String]$Message)
{
    $final = [DateTime]::Now.ToUniversalTime().ToString("s") + ":" + $Message
    $final | Out-File $logFile -Append
}

# Get the list of users with the ApplicationImpersonation RBAC role assignment
Write-LogFile "Listing users with ApplicationImpersonation RBAC role assignemnt: "
Write-Host
Write-Host "Listing users with ApplicationImpersonation RBAC role assignemnt:" -ForegroundColor Yellow

$roleUsers = Get-ManagementRoleAssignment -Role ApplicationImpersonation -GetEffectiveUsers | Where-Object {$_.EffectiveUserName -notlike "All Group Members"}

Write-LogFile "Effecitve User Names: $($roleUsers.EffectiveUserName)"
$roleUsers | Format-Table -AutoSize | Out-Host

# For each user, get their UPN and SID
Write-LogFile "Getting the UPN and SID of users with ApplicationImpersonation role assigned: "
Write-Host "Getting the UPN and SID of users with ApplicationImpersonation role assigned:" -ForegroundColor Yellow

$userSids = $roleUsers | ForEach-Object EffectiveUserName | Get-User | Select-Object UserPrincipalName,SID

Write-LogFile "UPNs: $($userSids.UserPrincipalName) | SIDs: $($userSids.Sid)"
$userSids | Out-Host

# Output the $userSids to CSV
$userSids | Export-Csv -Path $userSidsFile -NoTypeInformation

# Search the UAL for mailbox access activities so that we can look for LogonUserSids for SIDs matching the impersonation accounts and a different SID/UPN for MailboxOwnerSid/MailboxOwnerUPN
[DateTime]$currentStart = $start
[DateTime]$currentEnd = $end
$auditLogs = @()

Write-LogFile "BEGIN: Retrieving audit records between $($start) and $($end), Operations=$operations, PageSize=$resultSize."
Write-Host "Retrieving audit records for the date range between $($start) and $($end), Operations=$operations, ResultsSize=$resultSize" -ForegroundColor Yellow

$totalCount = 0
while ($true)
{
    $currentEnd = $currentStart.AddMinutes($intervalMinutes)
    if ($currentEnd -gt $end)
    {
        $currentEnd = $end
    }

    if ($currentStart -eq $currentEnd)
    {
        break
    }

    $sessionID = [Guid]::NewGuid().ToString() + "_" +  "ExtractLogs" + (Get-Date).ToString("yyyyMMddHHmmssfff")
    Write-LogFile "INFO: Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
    Write-Host "Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
    $currentCount = 0

    do
    {
        $results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -Operations $operations -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize
        $auditLogs += $results

        if (($results | Measure-Object).Count -ne 0)
        {
            $results | export-csv -Path $outputFile -Append -NoTypeInformation

            $currentTotal = $results[0].ResultCount
            $totalCount += $results.Count
            $currentCount += $results.Count
            Write-LogFile "INFO: Retrieved $($currentCount) audit records out of the total $($currentTotal)"

            if ($currentTotal -eq $results[$results.Count - 1].ResultIndex)
            {
                $message = "INFO: Successfully retrieved $($currentTotal) audit records for the current time range. Moving on!"
                Write-LogFile $message
                Write-Host "Successfully retrieved $($currentTotal) audit records for the current time range. Moving on to the next interval." -foregroundColor Yellow
                ""
                break
            }
        }
    }
    while (($results | Measure-Object).Count -ne 0)

    $currentStart = $currentEnd
}

Write-LogFile "END: Retrieving audit records between $($start) and $($end), RecordType=$record, PageSize=$resultSize, total count: $totalCount."
Write-Host "Finished retrieving audit records for the date range between $($start) and $($end). Total count: $totalCount" -foregroundColor Green

# Find events where AppImpersonation user is accessing a mailbox
Write-LogFile "Finding events where AppImpersonation user is accessing a mailbox - SID in Impersonation User list matches LogonUserSid in event."
Write-Host
Write-Host "Finding events where AppImpersonation user is accessing a mailbox." -ForegroundColor Yellow
Write-Host

$possibleHits = foreach ($user in $userSids) 
{
    foreach ($entry in $auditLogs)
    {
        if ($user.Sid -in ($entry.AuditData | ConvertFrom-Json).LogonUserSid)
        {
            $auditDetails = $entry.AuditData | ConvertFrom-Json
            $auditDetails | Add-Member NoteProperty -Name ImpersonationUser -Value $user.UserPrincipalName
            $auditDetails | Select-Object AppId,ImpersonationUser,MailboxOwnerUPN
        }
    }
}

# Filter events where the Impersonation User (LogonUserSid) and MailboxOwnerUPN are the same
Write-LogFile "Filtering events where the ImpersonationUser (LogonUserSid) and MailboxOwnerUPN are the same."
Write-Host
Write-Host "Filtering events that do not indicate Impersonation was being used." -ForegroundColor Yellow
Write-Host

$filteredData = @()
foreach ($possibleHit in $possibleHits) 
{
    if ($possibleHit.ImpersonationUser -ne $possibleHit.MailboxOwnerUPN) 
    {
        $filteredData += $possibleHit
    }
}

$filteredData | Export-Csv -Path $filteredResultsFile -NoTypeInformation

# Deduplicate data. Return data only for unique AppId + ImpersonationUser pairs. This effectively maps App Ids to the impersonation accounts being used by them. Comment out line below if you want the full output or are having issues with the data being received.
Write-LogFile "Deduplicating data, mapping App Ids to Impersonation users by finding unique AppId + ImpersonationUser pairs."
Write-Host
Write-Host "Deduplicating data, mapping Application Ids to Impersonation users." -ForegroundColor Yellow

$impersonationUserMapping = $filteredData | Group-Object AppId,ImpersonationUser | ForEach-Object {$_.Group | Select-Object -First 1} | Select-Object AppId,ImpersonationUser

$impersonationUserMapping | Export-Csv -Path $impersonationUserMappingFile -NoTypeInformation
$impersonationUserMapping | Format-Table -Property ImpersonationUser -GroupBy AppId

# Advise on next steps for admins
Write-Host "----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "PLEASE READ!" -ForegroundColor Yellow
Write-Host
Write-Host "At this point, you have the impacted App Ids and the accounts in use by these applications that are performing EWS Impersonation. IDENTIFY YOUR APPLICATION OWNERS AND CONTACT THEM so that they are aware of the deprecation of the ApplicationImpersonation RBAC role and implement the guidance outlined in https://aka.ms/applicationimpersonationdeprecation" -ForegroundColor Yellow
Write-Host
Write-Host "FAILURE TO UPDATE APPLICATIONS BY **MAY 2024** WILL RESULT in being unable to update existing ApplicationImpersonation role assignements, or make new assignments." -ForegroundColor Yellow
Write-Host
Write-Host "FAILURE TO UPDATE APPLICATIONS BY **FEBRUARY 2025** WILL RESULT in your impacted applications no longer working until they are updated." -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow