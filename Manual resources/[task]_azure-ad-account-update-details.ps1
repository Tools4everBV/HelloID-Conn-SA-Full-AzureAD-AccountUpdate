# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#Mapping variables from form
$displayName = $form.displayName;
$userPrincipalName = $form.gridUsers.UserPrincipalName;
$mailNickname = $form.mail.split("@")[0];
$mail = $form.mail
$givenName = $form.givenName
$surname = $form.surname
$jobTitle = $form.title
$department = $form.department
$companyName = $form.company
$mobilePhone = $form.mobilePhone
$businessPhones = $form.businessPhones

#Change mapping here
$account = [PSCustomObject]@{
    displayName = $displayName;
    userPrincipalName = $UserPrincipalName;
    mailNickname = $mailNickname;
    mail = $mail

    givenName = $givenName
    surname = $surname

    jobTitle = $jobTitle
    department = $department
    companyName = $companyName

    mobilePhone = $mobilePhone
    businessPhones = @($businessPhones)

    UsageLocation       =   "NL"
    PreferredLanguage   =   "NL"
}

# Filter out empty properties
$accountTemp = $account

$account = @{}
foreach($property in $accountTemp.PSObject.Properties){
    if(![string]::IsNullOrEmpty($property.Value)){
        $null = $account.Add($property.Name, $property.Value)
    }
}

$account = [PSCustomObject]$account


try{
    Write-Information "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    Write-Information "Updating AzureAD user [$($account.userPrincipalName)].."
 
    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $baseUpdateUri = "https://graph.microsoft.com/"
    $updateUri = $baseUpdateUri + "v1.0/users/$($account.userPrincipalName)"
    $body = $account | ConvertTo-Json -Depth 10
 
    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false

    Write-Information "AzureAD user [$($account.userPrincipalName)] updated successfully"

    $Log = @{
      Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
      System            = "AzureActiveDirectory" # optional (free format text) 
      Message           = "Updated account with username $($account.userPrincipalName)" # required (free format text) 
      IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
      TargetDisplayName = $form.displayName # optional (free format text) 
      TargetIdentifier  = $account.userPrincipalName # optional (free format text) 
  }
  #send result back  
  Write-Information -Tags "Audit" -MessageData $log

}catch{
    Write-Error "Error updating AzureAD user [$($account.userPrincipalName)]. Error: $_"
    Write-Information "Error updating AzureAD user [$($account.userPrincipalName)]" 

    $Log = @{
      Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
      System            = "AzureActiveDirectory" # optional (free format text) 
      Message           = "Error updateing account with username $($account.userPrincipalName). Error: $($_.Exception.Message)" # required (free format text) 
      IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
      TargetDisplayName = $form.displayName # optional (free format text)
  }
  #send result back  
  Write-Information -Tags "Audit" -MessageData $log
}
