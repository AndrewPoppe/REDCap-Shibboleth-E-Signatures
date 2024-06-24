<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

$module->log('logout request', [ 
    'get' => json_encode($_GET, JSON_PRETTY_PRINT),
    'post' => json_encode($_POST, JSON_PRETTY_PRINT),
    'cookie' => json_encode($_COOKIE, JSON_PRETTY_PRINT),
    'session' => json_encode($_SESSION, JSON_PRETTY_PRINT)
]);