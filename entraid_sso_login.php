<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

session_id($_COOKIE[EntraIdAuthenticator::ENTRAID_SESSION_ID_COOKIE]);
session_start();

[$session_id, $siteId, $originUrl] = explode('EIASEP', $_GET["state"]);
$authenticator = new Authenticator($module, $siteId);

$authData = $authenticator->getAuthData($session_id, $_GET["code"]);
$userData = $authenticator->getUserData($authData['access_token']);

if (isset($userData['error']) || empty($userData)) {
    $module->framework->log('Entra ID Authenticator Error', [ 'error' => json_encode($userData, JSON_PRETTY_PRINT) ]);
    exit($module->framework->tt('error_7'));
}

if (!$userData['accountEnabled']) {
    $module->framework->log('Entra ID Authenticator Unsuccessful login', [ 'userData' => json_encode($userData, JSON_PRETTY_PRINT) ]);
    exit($module->framework->tt('error_3'));
}

if (!$authenticator->checkGroupMembership($userData)) {
    $module->framework->log('Entra ID Authenticator No Valid Group Membership', [ 'userData' => json_encode($userData, JSON_PRETTY_PRINT) ]);
    exit($module->framework->tt('error_4'));
}

$result = $authenticator->loginEntraIDUser($userData, $originUrl);
if ( $result ) {

    \Session::deletecookie(EntraIdAuthenticator::ENTRAID_SESSION_ID_COOKIE);

    // strip the authtype parameters from the URL
    $redirectStripped = Utilities::stripQueryParameter($originUrl, EntraIdAuthenticator::AUTH_QUERY);
    $redirectStripped = Utilities::stripQueryParameter($redirectStripped, EntraIdAuthenticator::SITEID_QUERY);
    
    // Redirect to the page we were on
    header("Location: $redirectStripped");
}