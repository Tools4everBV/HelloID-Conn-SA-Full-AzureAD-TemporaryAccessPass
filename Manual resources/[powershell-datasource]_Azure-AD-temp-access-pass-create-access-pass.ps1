# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue" # / SilentlyContinue/Continue
$InformationPreference = "Continue"
$WarningPreference = "Continue"


try {
    $userID = $datasource.selecteduser.ID
    $userDisplayname = $datasource.selecteduser.displayname
    $lifetimeHours = $datasource.lifetimeHours
    $lifetimeMinutes = [int]$lifetimeHours * 60
    $startdate = [System.DateTime]::Parse((Get-Date).DateTime)
          
    Write-Verbose "Generating Microsoft Graph API Access Token.."
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AADAppId"
        client_secret = "$AADAppSecret"
        resource      = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;
    
    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept         = "application/json";
    }

    #create body for request
    $body = @{
        startDateTime     = $startdate
        lifetimeInMinutes = $lifetimeMinutes
        isUsableOnce      = $false
    }

    #building params voor request
    $params = @{
        uri     = "https://graph.microsoft.com/v1.0/users/$userID/authentication/temporaryAccessPassMethods"
        Method  = "POST"
        Headers = $authorization
        Verbose = $false
        body    = $body | convertto-json -depth 10
    }

    $result = Invoke-RestMethod @params

    $Log = @{
        Action            = "SetPassword" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Successfully generated Temporary Access Pass with lifetime $($result.lifetimeInMinutes) minutes" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $userDisplayname # optional (free format text) 
        TargetIdentifier  = $userID # optional (free format text) 
    }

    #send result back  
    Write-Information -Tags "Audit" -MessageData $log

    #create output result
    $output = $result | Select-Object -Property id, isUsable, temporaryAccessPass, lifetimeInMinutes, startDateTime, methodUsabilityReason, @{name = "lifetimeInHours"; Expression = { ($_.lifetimeInMinutes / 60) } }
    return $output

}
catch {
     
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error Temporary Access Pass. Error: $_" + $errorDetailsMessage)
    
    #return error in output    
    $output = @{temporaryAccessPass = "Error: $errorDetailsMessage" }
    return $output
}
  
