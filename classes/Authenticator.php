<?php

namespace YaleREDCap\EntraIdAuthenticator;

class Authenticator
{
    private $client_id;
    private $ad_tenant;
    private $client_secret;
    private $redirect_uri;
    private $redirect_uri_spa;
    private $module;
    private $session_id;
    private $logout_uri;
    private $allowedGroups;
    private $authType;
    private $entraIdSettings;
    public function __construct(EntraIdAuthenticator $module, string $authType, string $session_id = null)
    {
        $this->module          = $module;
        $this->authType        = $authType;
        $settings              = new EntraIdSettings($module);
        $this->entraIdSettings = $settings->getSettings($authType);
        if ( !$this->entraIdSettings ) {
            return;
        }
        $this->client_id        = $this->entraIdSettings['clientId'];  //Client ID, this is the Application ID from Azure
        $this->ad_tenant        = $this->entraIdSettings['adTenantId'];  //Azure AD Tenant ID
        $this->client_secret    = $this->entraIdSettings['clientSecret'];  //Client Secret, this is the secret key from Azure
        $this->redirect_uri     = $this->entraIdSettings['redirectUrl'];  //This needs to match 100% what is set in Entra ID
        $this->redirect_uri_spa = $this->entraIdSettings['redirectUrlSpa'];  //This needs to match 100% what is set in Entra ID
        $this->logout_uri       = $this->entraIdSettings['logoutUrl'];  //This needs to match 100% what is set in Entra ID
        $this->allowedGroups    = $this->entraIdSettings['allowedGroups'];
        $this->session_id       = $session_id ?? session_id();
    }

    public function authenticate(bool $refresh = false)
    {
        $url = "https://login.microsoftonline.com/" . $this->ad_tenant . "/oauth2/v2.0/authorize?";
        $url .= "state=" . $this->session_id . "AUTHTYPE" . $this->authType;
        $url .= "&scope=User.Read";
        $url .= "&response_type=code";
        $url .= "&approval_prompt=auto";
        $url .= "&client_id=" . $this->client_id;
        $url .= "&redirect_uri=" . urlencode($this->redirect_uri);
        $url .= $refresh ? "&prompt=login" : "";
        header("Location: " . $url);
        return;
    }

    public function getAuthData($state, $code)
    {
        //Checking if the state matches the session ID
        [ $sessionid, $authType ] = explode('AUTHTYPE', $state);
        $stateMatches           = strcmp(session_id(), $sessionid) == 0;
        if ( !$stateMatches ) {
            return;
        }

        //Verifying the received tokens with Azure and finalizing the authentication part
        $content = "grant_type=authorization_code";
        $content .= "&client_id=" . $this->client_id;
        $content .= "&redirect_uri=" . urlencode($this->redirect_uri);
        $content .= "&code=" . $code;
        $content .= "&client_secret=" . urlencode($this->client_secret);
        $options = array(
            "http" => array(  //Use "http" even if you send the request with https
                "method"  => "POST",
                "header"  => "Content-Type: application/x-www-form-urlencoded\r\n" .
                    "Content-Length: " . strlen($content) . "\r\n",
                "content" => $content
            )
        );
        $context = stream_context_create($options);
        $json    = file_get_contents("https://login.microsoftonline.com/" . $this->ad_tenant . "/oauth2/v2.0/token", false, $context);
        if ( $json === false ) {
            // errorhandler(array( "Description" => "Error received during Bearer token fetch.", "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options ), $error_email);
            return;
        }
        $authdata = json_decode($json, true);
        if ( isset($authdata["error"]) ) {
            // errorhandler(array( "Description" => "Bearer token fetch contained an error.", "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options ), $error_email);
            return;
        }

        return $authdata;
    }

    public function getUserData($access_token)
    {

        //Fetching the basic user information that is likely needed by your application
        $options = array(
            "http" => array(  //Use "http" even if you send the request with https
                "method" => "GET",
                "header" => "Accept: application/json\r\n" .
                    "Authorization: Bearer " . $access_token . "\r\n"
            )
        );
        $context = stream_context_create($options);
        $json    = file_get_contents("https://graph.microsoft.com/v1.0/me?\$select=id,mail,givenName,surname,onPremisesSamAccountName,companyName,department,jobTitle,userType,accountEnabled", false, $context);
        $json2   = file_get_contents("https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.group?\$select=displayName,id", false, $context);
        if ( $json === false ) {
            // errorhandler(array( "Description" => "Error received during user data fetch.", "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options ), $error_email);
            return;
        }

        $userdata = json_decode($json, true);  //This should now contain your logged on user information
        if ( isset($userdata["error"]) ) {
            // errorhandler(array( "Description" => "User data fetch contained an error.", "\$userdata[]" => $userdata, "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options ), $error_email);
            return;
        }

        $groupdata = json_decode($json2, true);

        $userdata_parsed = [
            'user_email'     => $userdata['mail'],
            'user_firstname' => $userdata['givenName'],
            'user_lastname'  => $userdata['surname'],
            'username'       => $userdata['onPremisesSamAccountName'],
            'company'        => $userdata['companyName'],
            'department'     => $userdata['department'],
            'job_title'      => $userdata['jobTitle'],
            'type'           => $userdata['userType'],
            'accountEnabled' => $userdata['accountEnabled'],
            'id'             => $userdata['id'],
            'groups'         => $groupdata['value']
        ];

        return $userdata_parsed;
    }

    public function checkGroupMembership($userData)
    {
        $userGroups = $userData['groups'];
        if ( empty($this->allowedGroups) ) {
            return true;
        }
        foreach ( $userGroups as $group ) {
            if ( in_array($group['id'], $this->allowedGroups) ) {
                return true;
            }
        }
        return false;
    }

    public function logout()
    {
        header("Location: " . $this->getLogoutUri());
        return;
    }

    public function getRedirectUri()
    {
        return $this->redirect_uri;
    }

    public function getRedirectUriSpa()
    {
        return $this->redirect_uri_spa;
    }

    public function getClientId()
    {
        return $this->client_id;
    }

    public function getAdTenant()
    {
        return $this->ad_tenant;
    }

    public function getLogoutUri()
    {
        return $this->logout_uri;
    }

}