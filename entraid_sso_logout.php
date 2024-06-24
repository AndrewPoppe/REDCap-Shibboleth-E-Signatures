<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

$module->log('logout request', [ 'get' => json_encode($_GET, JSON_PRETTY_PRINT) ]);