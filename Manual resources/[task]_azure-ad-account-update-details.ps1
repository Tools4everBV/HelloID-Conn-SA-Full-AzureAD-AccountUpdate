# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#Change mapping here
$account = [PSCustomObject]@{
    userType = $employeeType;
    displayName = $displayName;
    userPrincipalName = $userPrincipalName;
    mailNickname = $mail.split("@")[0];
    mail = $mail
    #showInAddressList = $true

    accountEnabled = $true;
    passwordProfile = @{
        password = $password
        forceChangePasswordNextSignIn = $false
    }

    givenName = $givenName
    surname = $surname

    jobTitle = $title
    department = $department
    officeLocation = $office
    companyName = $company

    mobilePhone = $mobilePhone
    businessPhones = @($businessPhones)
    faxNumber = $faxNumber

    employeeId = $employeeId

    UsageLocation       =   "NL"
    PreferredLanguage   =   "NL"

    #Country             =   "Netherlands"
    #State               =   "Utrecht"
    #City                =   "Baarn"
    #StreetAddress       =   "Amalialaan 126C"
    #PostalCode          =   "3743 KJ"
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
    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token.." -Event Information

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

    Hid-Write-Status -Message "Updating AzureAD user [$($account.userPrincipalName)].." -Event Information
 
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

    Hid-Write-Status -Message "AzureAD user [$($account.userPrincipalName)] updated successfully" -Event Success
    HID-Write-Summary -Message "AzureAD user [$($account.userPrincipalName)] updated successfully" -Event Success
}catch{
    HID-Write-Status -Message "Error updating AzureAD user [$($account.userPrincipalName)]. Error: $_" -Event Error
    HID-Write-Summary -Message "Error updating AzureAD user [$($account.userPrincipalName)]" -Event Failed
}
