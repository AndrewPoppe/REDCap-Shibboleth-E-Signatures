<?php

namespace YaleREDCap\ShibbolethEsignatures;

session_start();

$requestInstant = Authenticator::getEsignRequestTimestamp();
Authenticator::clearEsignRequestTimestamp();
$ShibAuthenticationInstant = Authenticator::getShibbolethAuthenticationInstant();
$timeDiff = $ShibAuthenticationInstant - $requestInstant;

if ($requestInstant < 0) {
    exit;
}

if ($ShibAuthenticationInstant < 0 || $timeDiff < 0) {
    $redirectUrl = Authenticator::getLoginUrl($module->getUrl('esign.php'));
    header("Location: " . $redirectUrl);
    exit;
}

$token = Authenticator::createToken();

$remoteUser = strtolower($_SERVER[trim($GLOBALS['shibboleth_username_field'])]);

?>
<script>
    window.opener.postMessage({success: true, token: '<?= $token ?>', user: '<?= $remoteUser ?>'});
    window.close();
</script>
