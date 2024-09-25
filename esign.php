<?php

namespace YaleREDCap\ShibbolethEsignatures;

session_start();

$requestInstant            = Authenticator::getEsignRequestTimestamp();
$ShibAuthenticationInstant = Authenticator::getShibbolethAuthenticationInstant();
$timeDiff                  = $ShibAuthenticationInstant - $requestInstant;

if ( $requestInstant < 0 ) {
    exit;
}

if ( $ShibAuthenticationInstant < 0 || $timeDiff < 0 ) {
    $redirectUrl = Authenticator::getLoginUrl($module->getUrl('esign.php'));
    header("Location: " . $redirectUrl);
    exit;
}

$token = Authenticator::createToken();
Authenticator::clearEsignRequestTimestamp();
$remoteUser = strtolower($_SERVER[trim($GLOBALS['shibboleth_username_field'])]);

$data     = [
    "token"                     => $token,
    "remoteUser"                => $remoteUser,
    "requestInstant"            => $requestInstant,
    "shibAuthenticationInstant" => $ShibAuthenticationInstant,
    "now"                       => time()
];
$dataJson = json_encode($data);

$encryptedData = encrypt($dataJson);

?>
<script>
    window.opener.postMessage({ success: true, data: '<?= $encryptedData ?>' });
    window.close();
</script>