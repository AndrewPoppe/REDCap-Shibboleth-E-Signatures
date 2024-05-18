<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

/** @var YaleREDCapAuthenticator $module */

session_id($_COOKIE['PHPSESSID2']);
session_start();

$originUrl     = $_COOKIE['entraid-yale-origin-url'];
$authenticator = new Yale_EntraID_Authenticator($module);

$authData = $authenticator->getAuthData($_GET["state"], $_GET["code"]);
$userData = $authenticator->getUserData($authData);

$result = $module->loginEntraIDUser($userData);
if ( $result ) {

    // \Session::deletecookie('entraid-yale-origin-url');
    // \Session::deletecookie('PHPSESSID2');
    unset($_SESSION['entraid-yale-user-data']);

    // strip the EntraID_auth and authed parameters from the URL
    $redirectStripped = $module->stripQueryParameter($originUrl, $module::$ENTRAID_AUTH);
    $redirectStripped = $module->stripQueryParameter($redirectStripped, 'authed');
    
    // Redirect to the page we were on
    header("Location: " . $redirectStripped);
}