<?php

namespace YaleREDCap\EntraIdEsignatures;

class Authenticator
{
    private $clientId;
    private $adTenant;
    private $clientSecret;
    private $redirectUriSpa;
    private $module;
    private array $entraIdSettings;
    private $adUsernameAttribute;

    const ERROR_MESSAGE_AUTHENTICATION = 'EntraIdEsignatures Authentication Error';
    public function __construct(EntraIdEsignatures $module)
    {
        $this->module          = $module;
        $this->entraIdSettings = $this->module->getSettings();
        if ( !$this->entraIdSettings ) {
            return;
        }
        $this->clientId            = $this->entraIdSettings['clientId'];
        $this->adTenant            = $this->entraIdSettings['adTenantId'];
        $this->clientSecret        = $this->entraIdSettings['clientSecret'];
        $this->redirectUriSpa      = $this->entraIdSettings['redirectUrlSpa'];
        $this->adUsernameAttribute = $this->entraIdSettings['adUsernameAttribute'];
    }



    /**
     * Get data from Entra ID using provided access token
     * @param string $accessToken
     * @return array
     */
    public function getUserData(string $accessToken) : array
    {
        $result = [];
        try {
            //Fetching the basic user information that is likely needed by your application
            $options = array(
                "http" => array(  //Use "http" even if you send the request with https
                    "method" => "GET",
                    "header" => "Accept: application/json\r\n" .
                        "Authorization: Bearer " . $accessToken . "\r\n"
                )
            );
            $context = stream_context_create($options);
            $json    = file_get_contents("https://graph.microsoft.com/v1.0/me?\$select=id,userPrincipalName,mail,givenName,surname,onPremisesSamAccountName,companyName,department,jobTitle,userType,accountEnabled", false, $context);
            if ( $json === false ) {
                $this->logError('Error received during user data fetch.');
                return $result;
            }

            $userdata = json_decode($json, true);  //This should now contain your logged on user information
            if ( isset($userdata["error"]) ) {
                $this->logError('User data fetch contained an error.');
                return $result;
            }

            $username       = $userdata[$this->adUsernameAttribute] ?? '';
            $username_clean = EntraIdEsignatures::toLowerCase($username);
            $email          = $userdata['mail'] ?? $userdata['userPrincipalName'];
            $email_clean    = EntraIdEsignatures::toLowerCase(filter_var($email, FILTER_VALIDATE_EMAIL));

            $result = [
                'user_email'     => $email_clean,
                'user_firstname' => $userdata['givenName'],
                'user_lastname'  => $userdata['surname'],
                'username'       => $username_clean,
                'company'        => $userdata['companyName'],
                'department'     => $userdata['department'],
                'job_title'      => $userdata['jobTitle'],
                'type'           => $userdata['userType'],
                'accountEnabled' => $userdata['accountEnabled'],
                'id'             => $userdata['id']
            ];
        } catch ( \Throwable $e ) {
            $this->logError($e->getMessage());
        }
        return $result;
    }

    private function logError(string $errorMessage) : void
    {
        $this->module->framework->log(self::ERROR_MESSAGE_AUTHENTICATION, [ 'error' => $errorMessage ]);
    }

    public function getRedirectUriSpa()
    {
        return $this->redirectUriSpa;
    }

    public function getClientId()
    {
        return $this->clientId;
    }

    public function getAdTenant()
    {
        return $this->adTenant;
    }
}