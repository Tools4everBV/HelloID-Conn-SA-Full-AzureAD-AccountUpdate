# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $searchValue = $datasource.searchUser
    $searchQuery = "*$searchValue*"
      
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        Hid-Add-TaskResult -ResultValue []
    }else{
        Write-Information "Searching for: $searchQuery"
          
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

        Write-Information "Searching for: $searchQuery"
        
        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }

        $properties = @("displayName","userPrincipalName","mail","accountEnabled","givenName","surname","department","jobTitle","companyName","businessPhones","mobilePhone")

        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/users" + '?$select=' + ($properties -join ",") + '&$top=999'
 
        $azureADUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADUsers = $azureADUsersResponse.value
        while (![string]::IsNullOrEmpty($azureADUsersResponse.'@odata.nextLink')) {
            $azureADUsersResponse = Invoke-RestMethod -Uri $azureADUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
            $azureADUsers += $azureADUsersResponse.value
        }  

        $users = foreach($azureADUser in $azureADUsers){
            if($azureADUser.displayName -like $searchQuery -or $azureADUser.userPrincipalName -like $searchQuery){
                $azureADUser
            }
        }
        $users = $users | Sort-Object -Property DisplayName
        $resultCount = @($users).Count
        Write-Information "Result count: $resultCount"
          
        if($resultCount -gt 0){
            foreach($user in $users){
                $returnObject = @{
                    displayName=$user.displayName;
                    userPrincipalName=$user.UserPrincipalName;
                    mail=$user.mail;
                    givenName=$user.givenName;
                    surname=$user.surname;
                    department=$user.department;
                    title=$user.jobTitle;
                    company=$user.companyName;
                    businessPhones=$user.businessPhones[0];
                    mobilePhone=$user.mobilePhone;
                }
                Write-Output $returnObject
            }
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD users. Error: $_" + $errorDetailsMessage)
}
  
