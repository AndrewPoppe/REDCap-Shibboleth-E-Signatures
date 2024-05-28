<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

session_id($_COOKIE[EntraIdAuthenticator::$ENTRAID_SESSION_ID_COOKIE]);
session_start();

$originUrl     = $_COOKIE[EntraIdAuthenticator::$ENTRAID_URL_COOKIE];

[$state, $authType] = explode('AUTHTYPE', $_GET["state"]);

$authenticator = new Authenticator($module, $authType);

$authData = $authenticator->getAuthData($state, $_GET["code"]);
$userData = $authenticator->getUserData($authData['access_token']);

if (!$userData['accountEnabled']) {
    exit($module->framework->tt('error_3'));
}

if (!$authenticator->checkGroupMembership($userData)) {
    exit($module->framework->tt('error_4'));
}

$result = $module->loginEntraIDUser($userData, $authType);
if ( $result ) {

    \Session::deletecookie(EntraIdAuthenticator::$ENTRAID_URL_COOKIE);
    \Session::deletecookie(EntraIdAuthenticator::$ENTRAID_SESSION_ID_COOKIE);

    // strip the authtype parameters from the URL
    $redirectStripped = $module->stripQueryParameter($originUrl, EntraIdAuthenticator::$AUTH_QUERY);
    
    // Redirect to the page we were on
    header("Location: " . $redirectStripped);
}