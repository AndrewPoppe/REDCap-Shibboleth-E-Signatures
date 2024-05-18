<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

/** @var YaleREDCapAuthenticator $module */

session_id($_COOKIE['PHPSESSID2']);
session_start();

$originUrl     = $_COOKIE['entraid-yale-origin-url'];
$authenticator = new Yale_EntraID_Authenticator($module, $originUrl);

$authData = $authenticator->getAuthData($_GET["state"], $_GET["code"]);
$userData = $authenticator->getUserData($authData);

$_SESSION['entraid-yale-user-data'] = $userData;

$url = $module->addQueryParameter($originUrl, 'authed', 'true');
header("Location: " . $url);
