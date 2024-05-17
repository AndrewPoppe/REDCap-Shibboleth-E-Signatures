<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

/** @var YaleREDCapAuthenticator $module */

session_id($_COOKIE['PHPSESSID2']);
session_start();
$module->log("Yale_EntraID_Authenticator 22", [ 'sessionid' => session_id() ]);
// if ( isset($_GET["error"]) ) {  //Second load of this page begins, but hopefully we end up to the next elseif section...
//     echo "Error handler activated:\n\n";
//     var_dump($_GET);  //Debug print
//     //errorhandler(array( "Description" => "Error received at the beginning of second stage.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION ), $error_email);
//     exit;
// }

$originUrl = $_COOKIE['entraid-yale-origin-url'];
$authenticator = new Yale_EntraID_Authenticator($module, $originUrl);

if (!isset($_GET["code"])) {
    $authenticator->authenticate();
    exit;
}

$authData = $authenticator->getAuthData($_GET["state"], $_GET["code"]);
$userData = $authenticator->getUserData($authData);

$_SESSION['entraid-yale-user-data'] = $userData;
$url                                = $module->addQueryParameter($originUrl, 'authed', 'true');

$module->log('Yale_EntraID_Authenticator 44', [ 'url' => $url, 'userData' => json_encode($userData, JSON_PRETTY_PRINT) ]);

header("Location: " . $url);
exit;

// echo '<pre>';
// var_dump($_GET);
// var_dump($_SESSION);
// var_dump($userData);
// echo '</pre>';

//If we end up here, something has obviously gone wrong... Likely a hacking attempt since sent and returned state aren't matching and no $_GET["error"] received.
// echo "Hey, please don't try to hack us!\n\n";
// echo "PHP Session ID used as state: " . session_id() . "\n";  //And for production version you likely don't want to show these for the potential hacker
// var_dump($_GET);  //But this being a test script having the var_dumps might be useful
//errorhandler(array( "Description" => "Likely a hacking attempt, due to state mismatch.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION ), $error_email);

// echo "\n<a href=\"" . $authenticator->getRedirectUri() . "\">Click here to redo the authentication</a>";  //Only to ease up your tests
