<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

/** @var YaleREDCapAuthenticator $module */

session_id($_COOKIE[YaleREDCapAuthenticator::$ENTRAID_SESSION_ID_COOKIE]);
session_start();

$originUrl     = $_COOKIE[YaleREDCapAuthenticator::$ENTRAID_URL_COOKIE];

[$state, $authType] = explode('AUTHTYPE', $_GET["state"]);

$authenticator = new Yale_EntraID_Authenticator($module, $authType);

$authData = $authenticator->getAuthData($state, $_GET["code"]);
$userData = $authenticator->getUserData($authData['access_token']);

if (!$userData['accountEnabled']) {
    exit('Your Entra ID account is not enabled. Please contact your administrator.');
}

if (!$authenticator->checkGroupMembership($userData)) {
    exit('You are not a member of an allowed group. Please contact your administrator.');
}

$result = $module->loginEntraIDUser($userData, $authType);
if ( $result ) {

    \Session::deletecookie(YaleREDCapAuthenticator::$ENTRAID_URL_COOKIE);
    \Session::deletecookie(YaleREDCapAuthenticator::$ENTRAID_SESSION_ID_COOKIE);

    // strip the authtype parameters from the URL
    $redirectStripped = $module->stripQueryParameter($originUrl, YaleREDCapAuthenticator::$AUTH_QUERY);
    
    // Redirect to the page we were on
    header("Location: " . $redirectStripped);
}