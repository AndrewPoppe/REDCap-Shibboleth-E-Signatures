<?php

namespace YaleREDCap\ShibbolethEsignatures;

/** @var ShibbolethEsignatures $module */

try {
    $logoutUrl = $module->getIdPLogoutUrlGeneral() ?: APP_PATH_WEBROOT_FULL . '?logout=1';

    // Logout from REDCap
    \Logging::logPageView("LOGOUT", $_SESSION['username']);
    \Session::destroyUserSession();

    // Logout from IdP
    header("Location: " . $logoutUrl);
} catch (\Throwable $e) {
    $module->framework->log(ShibbolethEsignatures::MODULE_TITLE . ': Error logging out', ['error' => $e->getMessage()]);
    \Authentication::checkLogout();
}