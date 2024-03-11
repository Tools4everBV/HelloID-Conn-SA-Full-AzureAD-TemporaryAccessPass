# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$blnchangenextsignin = $form.blnchangenextsignin
$blnenable = $form.blnenable
$blnreset = $form.blnreset
$password = $form.password
$userPrincipalName = $form.gridUsers.UserPrincipalName
$id = $form.gridUsers.Id
$DisplayName = $form.gridUsers.DisplayName

Write-Warning "Reset password: $blnreset"
Write-Warning "Enable account: $blnenable"
Write-Warning "Force Change Password Next SignIn: $blnchangenextsignin"

#Change mapping here
if ($blnreset -eq 'true') {
    $account = [PSCustomObject]@{
        id                = $id
        userPrincipalName = $userPrincipalName
        accountEnabled    = $blnenable
        passwordProfile   = @{
            password                      = $password
            forceChangePasswordNextSignIn = $blnchangenextsignin
        }
    }
}
elseif ($blnreset -eq 'false') {   
    $account = [PSCustomObject]@{
        id                = $id
        userPrincipalName = $userPrincipalName
        accountEnabled    = $blnenable
    }
}

try {
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
    $accessToken = $Response.access_token

    Write-Information "Updating AzureAD user [$($account.userPrincipalName) ($($account.id))].."
 
    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }
 
    $baseUpdateUri = "https://graph.microsoft.com/"
    $updateUri = $baseUpdateUri + "v1.0/users/$($account.id)"
    $body = $account | ConvertTo-Json -Depth 10
 
 
    $response = Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false
    
    Write-Information "AzureAD user [$($account.userPrincipalName) ($($account.id))] updated successfully"

    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "AzureAD user [$($account.userPrincipalName) ($($account.id))] updated successfully" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $DisplayName # optional (free format text) 
        TargetIdentifier  = $([string]$AADTenantID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log

}
catch {
    Write-Error "Error updating AzureAD user [$($account.userPrincipalName) ($($account.id))]. Error: $_"

    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Error updating AzureAD user [$($account.userPrincipalName) ($($account.id))]" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $DisplayName # optional (free format text) 
        TargetIdentifier  = $([string]$AADTenantID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
    
}
