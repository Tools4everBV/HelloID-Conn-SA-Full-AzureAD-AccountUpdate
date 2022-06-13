# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Azure Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = @'
430009f2-92ac-4e8b-a877-57e2d5ad01a0gtds
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> companyName
$tmpName = @'
companyName
'@ 
$tmpValue = @'
{{company.name}}
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> AADtenantID
$tmpName = @'
AADtenantID
'@ 
$tmpValue = @'
661b4604-5b86-4336-aaae-00550f991c6bhfdr
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> AADAppSecret
$tmpName = @'
AADAppSecret
'@ 
$tmpValue = @'
hRL8Q~Q1bsHzQVaKwulNq5fIh~RGvM.xmgxPZcCs
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Azure-AD-User-update-generate-table-attributes-basic" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $userPrincipalName = $datasource.selectedUser.UserPrincipalName

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
         
    Write-Information "Searching for AzureAD user userPrincipalName=$userPrincipalName"

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $properties = @("displayName","userPrincipalName","mail","accountEnabled","givenName","surname","department","jobTitle","companyName","businessPhones","mobilePhone")
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName" + '?$select=' + ($properties -join ",")
    $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    Write-Information "Finished searching AzureAD user [$userPrincipalName]"

    # Get first object of array in businessPhones (HelloID doesn't support multivalue)
    $azureADUser.businessPhones =  $azureADUser.businessPhones[0] 

    foreach($tmp in $azureADUser.psObject.properties)
    {
        if($tmp.Name -in $properties){
            $returnObject = [Ordered]@{
                name=$tmp.Name;
                value=$tmp.value
            }
            Write-Output $returnObject
        }
    }
   
    Write-Information "Finished retrieving AzureAD user [$userPrincipalName] basic attributes"
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for AzureAD groups. Error: $_" + $errorDetailsMessage)
}
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"value","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Azure-AD-User-update-generate-table-attributes-basic
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Azure-AD-User-update-generate-table-attributes-basic" #>

<# Begin: DataSource "Azure-AD-User-update-generate-table-wildcard" #>
$tmpPsScript = @'
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
  
'@ 
$tmpModel = @'
[{"key":"company","type":0},{"key":"displayName","type":0},{"key":"mobilePhone","type":0},{"key":"department","type":0},{"key":"title","type":0},{"key":"businessPhones","type":0},{"key":"userPrincipalName","type":0},{"key":"mail","type":0},{"key":"givenName","type":0},{"key":"surname","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"searchUser","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Azure-AD-User-update-generate-table-wildcard
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Azure-AD-User-update-generate-table-wildcard" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Azure AD Account - Update details" #>
$tmpSchema = @"
[{"label":"Select user account","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":"Username or email address"},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridUsers","templateOptions":{"label":"Select user account","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"displayName"},{"headerName":"UserPrincipalName","field":"userPrincipalName"},{"headerName":"Mail","field":"mail"},{"headerName":"Given Name","field":"givenName"},{"headerName":"Surname","field":"surname"},{"headerName":"Title","field":"title"},{"headerName":"Department","field":"department"},{"headerName":"Company","field":"company"},{"headerName":"Mobile Phone","field":"mobilePhone"},{"headerName":"Business Phones","field":"businessPhones"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchUser","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Details","fields":[{"key":"gridDetails","templateOptions":{"label":"Basic attributes","required":false,"grid":{"columns":[{"headerName":"Name","field":"name"},{"headerName":"Value","field":"value"}],"height":350,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true},{"key":"displayName","templateOptions":{"label":"Display Name","useDataSource":false,"displayField":"displayName","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"displayName"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"givenName","templateOptions":{"label":"Given name","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"givenName"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"surname","templateOptions":{"label":"Surname","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"surname"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"mail","templateOptions":{"label":"Mail","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"mail","placeholder":""},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"title","templateOptions":{"label":"Job title","useDataSource":false,"displayField":"title","useFilter":false,"useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"title"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"department","templateOptions":{"label":"Department","useDataSource":false,"displayField":"department","useFilter":false,"useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"department"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"company","templateOptions":{"label":"Company","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"company","placeholder":"","useDataSource":false},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"mobilePhone","templateOptions":{"label":"Mobile phone","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"mobilePhone"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"businessPhones","templateOptions":{"label":"Business Phone","useDependOn":true,"dependOn":"gridUsers","dependOnProperty":"businessPhones"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Azure AD Account - Update details
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Azure AD Account - Update details
'@
$tmpTask = $null 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Automation Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
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
'@; 

	$tmpVariables = @'
[{"name":"title","value":"{{form.title}}","secret":false,"typeConstraint":"string"},{"name":"givenName","value":"{{form.givenName}}","secret":false,"typeConstraint":"string"},{"name":"userPrincipalName","value":"{{form.gridUsers.UserPrincipalName}}","secret":false,"typeConstraint":"string"},{"name":"mobilePhone","value":"{{form.mobilePhone}}","secret":false,"typeConstraint":"string"},{"name":"department","value":"{{form.department}}","secret":false,"typeConstraint":"string"},{"name":"surname","value":"{{form.surname}}","secret":false,"typeConstraint":"string"},{"name":"company","value":"{{form.company}}","secret":false,"typeConstraint":"string"},{"name":"telephoneNumber","value":"{{form.telephoneNumber}}","secret":false,"typeConstraint":"string"},{"name":"mobileNumber","value":"{{form.mobileNumber}}","secret":false,"typeConstraint":"string"},{"name":"businessPhones","value":"{{form.businessPhones}}","secret":false,"typeConstraint":"string"},{"name":"displayName","value":"{{form.displayName}}","secret":false,"typeConstraint":"string"},{"name":"mail","value":"{{form.mail}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormAutomationTaskGUID = [PSCustomObject]@{} 
	$delegatedFormAutomationTaskName = @'
azure-ad-account-update-details
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormAutomationTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormAutomationTaskGUID) 
} else {
	Write-Warning "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form automation task..." 
}
<# End: Delegated Form Automation Task #>
