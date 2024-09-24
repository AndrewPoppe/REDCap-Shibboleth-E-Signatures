<?php

namespace YaleREDCap\ShibbolethEsignatures;

$requestInstant = Authenticator::getEsignRequestTimestamp();
$ShibAuthenticationInstant = $_SERVER['Shib-Authentication-Instant'] ?? -1;
$timeDiff = $ShibAuthenticationInstant - $requestInstant;

if ($requestInstant < 0) {
    $module->log('request instant no good', []);
    exit;
}

if ($ShibAuthenticationInstant < 0 || $timeDiff < 0) {
    $redirectUrl = Authenticator::getLoginUrl($module->getUrl('esign.php'));
    $module->log('redirecting to ' . $redirectUrl, []);
    header("Location: " . $redirectUrl);
}

Authenticator::clearEsignRequestTimestamp();

$remoteUser = strtolower($_SERVER[trim($_GLOBALS['shibboleth_username_field'])]);

$module->log('signed in!', ['shibuser' => $remoteUser]);

$token = 'abcdef';

?>
<script>
    window.opener.postMessage({success: true, token: <?= $token ?>, user: '<?= $remoteUser ?>'});
    window.close();
</script>
