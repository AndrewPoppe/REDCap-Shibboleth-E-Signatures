<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

$authenticator = new Authenticator($module, '');
$authenticator->handleLogout();
