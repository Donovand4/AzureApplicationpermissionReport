#############################################################################  
#                                                                           #  
#   This Sample Code is provided for the purpose of illustration only       #  
#   and is not intended to be used in a production environment.  THIS       #  
#   SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT    #  
#   WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT    #  
#   LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS     #  
#   FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free    #  
#   right to use and modify the Sample Code and to reproduce and distribute #  
#   the object code form of the Sample Code, provided that You agree:       #  
#   (i) to not use Our name, logo, or trademarks to market Your software    #  
#   product in which the Sample Code is embedded; (ii) to include a valid   #  
#   copyright notice on Your software product in which the Sample Code is   #  
#   embedded; and (iii) to indemnify, hold harmless, and defend Us and      #  
#   Our suppliers from and against any claims or lawsuits, including        #  
#   attorneys' fees, that arise or result from the use or distribution      #  
#   of the Sample Code.                                                     # 
#                                                                           # 
#   This posting is provided "AS IS" with no warranties, and confers        # 
#   no rights.                                                              #
#                                                                           #  
#############################################################################  
cls
try 
{
  Get-AzureADTenantDetail | Out-Null
} 
catch 
{ 
  Connect-AzureAD | Out-Null 
} 
 
Write-Host "Collecting Azure AD Application Information" -ForegroundColor Green 
try 
{ 
  $AllServicePrincipals = Get-AzureADServicePrincipal -All:$true | where-object {$_.tags -eq "WindowsAzureActiveDirectoryIntegratedApp"}
} 
catch 
{ 
  Write-Host "Please Authenticate to AzureAD before Continuing!" -ForegroundColor Red -ErrorAction Stop 
}

function Get-ApplicationPasswordCredentials 
{
  param (
      [Parameter(Mandatory=$true)]      
      $AppID
  )
  $expiredCount = 0
  $NonExpired = 0
  $applications = (Get-AzureADApplication -All:$true | where {$_.AppID -eq $AppID}).passwordcredentials.enddate
  foreach ($expirydate in $applications) 
  {
    switch ($expirydate) 
    {
    { $expirydate -gt $date } { $NonExpired++ }
    $null { return "N/A" }
    { $expirydate -lt $date } { $expiredCount++ }    
    }  
    if ($expiredCount -gt 0)
    {
    return "Expired"
    }
    elseif ($NonExpired -eq ($applications | Measure-Object).count)
    {
      return "Current"
    }
  }
}

function Get-ApplicationKeyCredentials 
{
  param (
      [Parameter(Mandatory=$true)]      
      $AppID
  )
  $expiredKeyCount = 0
  $NonKeyExpired = 0
  $applications = (Get-AzureADApplication -All:$true | where {$_.AppID -eq $AppID}).KeyCredentials.enddate
  foreach ($expirydate in $applications) 
  {
    switch ($expirydate) 
    {
    { $expirydate -gt $date } { $NonKeyExpired++ }
    $null { return "N/A" }
    { $expirydate -lt $date } { $expiredKeyCount++ }    
    }  
    if ($expiredCount -gt 0)
    {
    return "Expired"
    }
    elseif ($NonKeyExpired -eq ($applications | Measure-Object).count)
    {
      return "Current"
    }
  }
}


$Report = @()
$Date = Get-Date
foreach ($SP in $AllServicePrincipals) 
{ 
  #Report on Application level permissions
  $ApplicationPermissions = @()      
  foreach ($RoleAssignment in (Get-AzureADServiceAppRoleAssignedTo -ObjectId $SP.ObjectID )) {         
      $AppRole = (Get-AzureADServicePrincipal -ObjectId $RoleAssignment.ResourceId).AppRoles | Where-Object {$_.ID -eq $RoleAssignment.ID}
      $permission = "[" + $RoleAssignment.ResourceDisplayName + "]:" + $AppRole.Value 
    $ApplicationPermissions += $permission
  }
  $ApplicationPermissions = $ApplicationPermissions -join ","

  #get all delegated application permissions
    $SPperm = Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $SP.ObjectId -All:$true
    $OAuthperm = @{}; 
    $assignedto = @();$resID = $null; $userId = $null;    

    $SPperm | % {#CAN BE DIFFERNT FOR DIFFERENT USERS! 
        $resID = (Get-AzureADObjectByObjectId -ObjectIds $_.ResourceId).DisplayName 
        if ($_.PrincipalId) 
        { 
            $userId = "(" + (Get-AzureADObjectByObjectId -ObjectIds $_.PrincipalId).UserPrincipalName + ")" 
        } 

        $OAuthperm["[" + $resID + $userId + "]"] = (($_.Scope.Trim().Split(" ") | Select-Object -Unique) -join ",") 
    } 

#Authorized by
if (($SPperm.ConsentType | Select-Object -Unique) -eq "AllPrincipals") { $assignedto += "All users (admin consent)" } 
try { $assignedto += (Get-AzureADObjectByObjectId -ObjectIds ($SPperm.PrincipalId | Select-Object -Unique)).UserPrincipalName } 
catch {}
    
  $ReportItems = New-Object PSObject
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "Application" -Value $SP.DisplayName 
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "ApplicationId" -Value $SP.AppId
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "ObjectID" -Value $SP.ObjectID
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "Publisher" -Value $SP.PublisherName 
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "Homepage" -Value $SP.Homepage 
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "Enabled" -Value $SP.AccountEnabled
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "PasswordStatus" -Value (Get-ApplicationPasswordCredentials -AppID $SP.AppId)  
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "PasswordDates" -Value ((Get-AzureADApplication -All:$true | where {$_.AppID -eq $SP.AppId}).passwordcredentials.enddate -join ", ")
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "CertStatus" -Value (Get-ApplicationKeyCredentials -AppID $SP.AppId)
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "CertDates" -Value ((Get-AzureADApplication -All:$true | where {$_.AppID -eq $SP.AppId}).KeyCredentials.enddate -join ", ")
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "AuthorizedBy" -Value ($assignedto -join ", ")
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "ApplicationPermissions" -Value $ApplicationPermissions
  Add-Member -InputObject $ReportItems -MemberType NoteProperty -Name "DelegatedPermissions" -Value (($OAuthperm.GetEnumerator() | % { "$($_.Name):$($_.Value)" }) -join ";")
  $Report += $ReportItems 
}

$Report | select Application, ApplicationID, ObjectID, Publisher, Homepage, Enabled, PasswordStatus, PasswordDates, CertStatus, CertDates, AuthorizedBy, ApplicationPermissions, DelegatedPermissions | Export-Csv "$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))_AppInventory.csv" -NoTypeInformation
