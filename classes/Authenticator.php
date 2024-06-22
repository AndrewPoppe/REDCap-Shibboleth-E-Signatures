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
    private $siteId;
    private $authType;
    private $settings;
    private $entraIdSettings;
    public function __construct(EntraIdAuthenticator $module, string $siteId, string $session_id = null)
    {
        $this->module          = $module;
        $this->siteId          = $siteId;
        $this->session_id      = $session_id ?? session_id();
        $this->settings        = new EntraIdSettings($module);
        $this->entraIdSettings = $this->settings->getSettings($siteId);
        if ( !$this->entraIdSettings ) {
            return;
        }
        $this->setSiteAttributes();
    }

    public function authenticate(bool $refresh = false, string $originUrl = '')
    {
        $url = "https://login.microsoftonline.com/" . $this->ad_tenant . "/oauth2/v2.0/authorize?";
        $url .= "state=" . $this->session_id . "EIASEP" . $this->siteId . "EIASEP" . urlencode($originUrl);
        $url .= "&scope=User.Read";
        $url .= "&response_type=code";
        $url .= "&approval_prompt=auto";
        $url .= "&client_id=" . $this->client_id;
        $url .= "&redirect_uri=" . urlencode($this->redirect_uri);
        $url .= $refresh ? "&prompt=login" : "";
        header("Location: " . $url);
        return;
    }

    public function getAuthData($session_id, $code)
    {
        //Checking if the state matches the session ID
        $stateMatches = strcmp(session_id(), $session_id) == 0;
        if ( !$stateMatches ) {
            $this->module->framework->log('EntraIdAuthenticator Authentication Error', [ 'error' => 'State does not match session ID' ]);
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
            $this->module->framework->log('EntraIdAuthenticator Authentication Error', [ 'error' => 'Error received during Bearer token fetch.' ]);
            return;
        }
        $authdata = json_decode($json, true);
        if ( isset($authdata["error"]) ) {
            $this->module->framework->log('EntraIdAuthenticator Authentication Error', [ 'error' => 'Bearer token fetch contained an error.' ]);
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
            $this->module->framework->log('EntraIdAuthenticator Authentication Error', [ 'error' => 'Error received during user data fetch.' ]);
            return;
        }

        $userdata = json_decode($json, true);  //This should now contain your logged on user information
        if ( isset($userdata["error"]) ) {
            $this->module->framework->log('EntraIdAuthenticator Authentication Error', [ 'error' => 'User data fetch contained an error.' ]);
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

    public function setSiteAttributes()
    {
        $this->siteId           = $this->entraIdSettings['siteId'];
        $this->authType         = $this->entraIdSettings['authValue'];
        $this->client_id        = $this->entraIdSettings['clientId'];
        $this->ad_tenant        = $this->entraIdSettings['adTenantId'];
        $this->client_secret    = $this->entraIdSettings['clientSecret'];
        $this->redirect_uri     = $this->entraIdSettings['redirectUrl'];
        $this->redirect_uri_spa = $this->entraIdSettings['redirectUrlSpa'];
        $this->logout_uri       = $this->entraIdSettings['logoutUrl'];
        $this->allowedGroups    = $this->entraIdSettings['allowedGroups'];
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

    public function handleEntraIDAuth($authType, $url)
    {
        try {
            $session_id = session_id();
            \Session::savecookie(EntraIdAuthenticator::$ENTRAID_SESSION_ID_COOKIE, $session_id, 0, true);
            $this->entraIdSettings = $this->settings->getSettingsByAuthValue($authType);
            $this->setSiteAttributes();
            $this->authenticate(false, $url);
            return true;
        } catch ( \Throwable $e ) {
            $this->module->framework->log('Entra ID REDCap Authenticator: Error 1', [ 'error' => $e->getMessage() ]);
            session_unset();
            session_destroy();
            return false;
        }
    }

    public function loginEntraIDUser(array $userdata, string $originUrl)
    {
        global $enable_user_allowlist, $homepage_contact, $homepage_contact_email, $lang, $userid;
        try {
            $username = $userdata['username'];
            if ( $username === false || empty($username) ) {
                return false;
            }

            // Check if user exists in REDCap, if not and if we are not supposed to create them, leave
            $users = new Users($this->module);
            if ( !$users->userExists($username) && !$this->module->framework->getSystemSetting('create-new-users-on-login') == 1 ) {
                exit($this->module->framework->tt('error_2'));
            }

            // Force custom attestation page if needed
            $attestation = new Attestation($this->module, $username, $this->siteId);
            if ( $attestation->needsAttestation() ) {
                $attestation->showAttestationPage($userdata, $originUrl);
                return false;
            }

            // Successful authentication
            $this->module->framework->log('Entra ID REDCap Authenticator: Auth Succeeded', [
                "EntraID Username" => $username
            ]);

            // Trigger login
            \Authentication::autoLogin($username);
            $_SESSION['entraid_id'] = $userdata['id'];

            // Update last login timestamp
            \Authentication::setUserLastLoginTimestamp($username);

            // Log the login
            \Logging::logPageView("LOGIN_SUCCESS", $username);

            // Handle account-related things.
            // If the user does not exist, create them.
            if ( !$users->userExists($username) ) {
                $users->createUser($username, $userdata);
                $users->setEntraIdUser($username, $this->siteId);
            }

            // If user does not have an email address or email has not been verified, show update screen
            if ( !$this->module->userHasVerifiedEmail($username) ) {
                $userid = $username;
                $this->module->showEmailUpdatePage();
                return false;
            }

            // If user is a table-based user, convert to Entra ID user
            elseif ( \Authentication::isTableUser($username) && $this->module->framework->getSystemSetting('convert-table-user-to-entraid-user') == 1 ) {
                $users->convertTableUserToEntraIdUser($username, $this->siteId);
            }
            // otherwise just make sure they are logged as an Entra ID user
            elseif ( !\Authentication::isTableUser($username) ) {
                $users->setEntraIdUser($username, $this->siteId);
            }

            // 2. If user allowlist is not enabled, all Entra ID users are allowed.
            // Otherwise, if not in allowlist, then give them an error page.
            if ( !$this->module->checkAllowlist($username) ) {
                $this->module->showNoUserAccessPage($username);
                return false;
            }
            return true;
        } catch ( \Throwable $e ) {
            $this->module->framework->log('Entra ID REDCap Authenticator: Error 2', [ 'error' => $e->getMessage() ]);
            session_unset();
            session_destroy();
            return false;
        }
    }

    public function handleLogout()
    {
        $users                 = new Users($this->module);
        $site                  = $users->getUserType();
        $this->entraIdSettings = $this->settings->getSettings($site['siteId']);
        $this->setSiteAttributes();
        session_unset();
        session_destroy();
        $this->logout();
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

    public function getAuthType()
    {
        return $this->authType;
    }

}