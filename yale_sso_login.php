<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

/** @var YaleREDCapAuthenticator $module */

session_id($_COOKIE[YaleREDCapAuthenticator::$ENTRAID_SESSION_ID_COOKIE]);
session_start();

$originUrl     = $_COOKIE[YaleREDCapAuthenticator::$ENTRAID_URL_COOKIE];
$authenticator = new Yale_EntraID_Authenticator($module);

$authData = $authenticator->getAuthData($_GET["state"], $_GET["code"]);
$userData = $authenticator->getUserData($authData['access_token']);

$result = $module->loginEntraIDUser($userData);
if ( $result ) {

    \Session::deletecookie(YaleREDCapAuthenticator::$ENTRAID_URL_COOKIE);
    \Session::deletecookie(YaleREDCapAuthenticator::$ENTRAID_SESSION_ID_COOKIE);
    unset($_SESSION['entraid-yale-user-data']);

    // strip the EntraID_auth and authed parameters from the URL
    $redirectStripped = $module->stripQueryParameter($originUrl, YaleREDCapAuthenticator::$ENTRAID_AUTH);
    
    // Redirect to the page we were on
    header("Location: " . $redirectStripped);
}