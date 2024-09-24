<?php

namespace YaleREDCap\ShibbolethEsignatures;

session_start();

$requestInstant = Authenticator::getEsignRequestTimestamp();
$ShibAuthenticationInstant = Authenticator::getShibbolethAuthenticationInstant();
$timeDiff = $ShibAuthenticationInstant - $requestInstant;

$module->log('info', [ 'ri' => $requestInstant, 'si' => $ShibAuthenticationInstant, 'diff' => $timeDiff ]);

if ($requestInstant < 0) {
    $module->log('request instant no good', []);
    exit;
}

if ($ShibAuthenticationInstant < 0 || $timeDiff < 0) {
    $redirectUrl = Authenticator::getLoginUrl($module->getUrl('esign.php'));
    $module->log('redirecting to ' . $redirectUrl, []);
    header("Location: " . $redirectUrl);
    exit;
}

Authenticator::clearEsignRequestTimestamp();
$token = Authenticator::createToken();

$remoteUser = strtolower($_SERVER[trim($GLOBALS['shibboleth_username_field'])]);

$module->log('signed in!', ['shibuser' => $remoteUser, 'token' => $token]);

?>
<script>
    window.opener.postMessage({success: true, token: '<?= $token ?>', user: '<?= $remoteUser ?>'});
    window.close();
</script>
