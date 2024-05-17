<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

/** @var YaleREDCapAuthenticator $module */

function errorhandler($input, $email)
{
    $output = "PHP Session ID:    " . session_id() . PHP_EOL;
    $output .= "Client IP Address: " . getenv("REMOTE_ADDR") . PHP_EOL;
    $output .= "Client Browser:    " . $_SERVER["HTTP_USER_AGENT"] . PHP_EOL;
    $output .= PHP_EOL;
    ob_start();  //Start capturing the output buffer
    var_dump($input);  //This is not for debug print, this is to collect the data for the email
    $output .= ob_get_contents();  //Storing the output buffer content to $output
    ob_end_clean();  //While testing, you probably want to comment the next row out
    mb_send_mail($email, "Your Entra ID Oauth2 script faced an error!", $output, "X-Priority: 1\nContent-Transfer-Encoding: 8bit\nX-Mailer: PHP/" . phpversion());
    exit;
}

$authenticator = new Yale_EntraID_Authenticator($module);

if ( !isset($_GET["code"]) and !isset($_GET["error"]) ) {  //Real authentication part begins
    $authenticator->authenticate();
    exit;
} 

if ( isset($_GET["error"]) ) {  //Second load of this page begins, but hopefully we end up to the next elseif section...
    echo "Error handler activated:\n\n";
    var_dump($_GET);  //Debug print
    //errorhandler(array( "Description" => "Error received at the beginning of second stage.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION ), $error_email);
    exit;
} 

$authData = $authenticator->getAuthData($_GET["state"], $_GET["code"]);
$userData = $authenticator->getUserData($authData);

echo '<pre>';
var_dump($_SESSION);
var_dump($userData);
echo '</pre>';

    //If we end up here, something has obviously gone wrong... Likely a hacking attempt since sent and returned state aren't matching and no $_GET["error"] received.
    // echo "Hey, please don't try to hack us!\n\n";
    // echo "PHP Session ID used as state: " . session_id() . "\n";  //And for production version you likely don't want to show these for the potential hacker
    // var_dump($_GET);  //But this being a test script having the var_dumps might be useful
    //errorhandler(array( "Description" => "Likely a hacking attempt, due to state mismatch.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION ), $error_email);

echo "\n<a href=\"" . $authenticator->getRedirectUri() . "\">Click here to redo the authentication</a>";  //Only to ease up your tests