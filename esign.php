<?php

namespace YaleREDCap\ShibbolethEsignatures;

session_start();

$requestInstant            = Authenticator::getEsignRequestTimestamp();
$ShibAuthenticationInstant = Authenticator::getShibbolethAuthenticationInstant();
$timeDiff                  = $ShibAuthenticationInstant - $requestInstant;

// No valid timestamp saved for this e-signature request
if ( $requestInstant < 0 ) {
    echo 'Error e-signing. Please close this window and try again.';
    exit;
}

$requestInstantAge = time() - $requestInstant;
// Request is too old
if ( $requestInstantAge > ShibbolethEsignatures::MAX_REQUEST_AGE_SECONDS ) {
    echo 'Error e-signing. Please close this window and try again.';
    exit;
}

// No valid shib session or shib authentication happened before the e-signature request
// Need to re-authenticate
if ( $ShibAuthenticationInstant < 0 || $timeDiff < 0 ) {
    $redirectUrl = Authenticator::getLoginUrl($module->getUrl('esign.php'));
    header("Location: " . $redirectUrl);
    exit;
}

// Re-authnetication was successful
// Set some tokens to make sure requests match etc.
$token = Authenticator::createToken();
Authenticator::clearEsignRequestTimestamp();

// Get username of successfully authenticated user
$shibboleth_username_field = trim($GLOBALS['shibboleth_username_field'] ?? '');
$remoteUser                = strtolower($_SERVER[$shibboleth_username_field] ?? '');

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
    window.opener.postMessage({ success: true, data: '<?= $encryptedData ?>', username: '<?= $remoteUser ?>' });
    window.close();
</script>