<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

session_id($_COOKIE[EntraIdAuthenticator::ENTRAID_SESSION_ID_COOKIE]);
session_start();

[$session_id, $siteId, $originUrl] = explode('EIASEP', $_GET["state"]);
$authenticator = new Authenticator($module, $siteId);

$authData = $authenticator->getAuthData($session_id, $_GET["code"]);
$userData = $authenticator->getUserData($authData['access_token']);

if (!$userData['accountEnabled']) {
    exit($module->framework->tt('error_3'));
}

if (!$authenticator->checkGroupMembership($userData)) {
    exit($module->framework->tt('error_4'));
}

$result = $authenticator->loginEntraIDUser($userData, $originUrl);
if ( $result ) {

    \Session::deletecookie(EntraIdAuthenticator::ENTRAID_SESSION_ID_COOKIE);

    // strip the authtype parameters from the URL
    $redirectStripped = Utilities::stripQueryParameter($originUrl, EntraIdAuthenticator::AUTH_QUERY);
    $redirectStripped = Utilities::stripQueryParameter($redirectStripped, EntraIdAuthenticator::SITEID_QUERY);
    
    // Redirect to the page we were on
    header("Location: " . $redirectStripped);
}