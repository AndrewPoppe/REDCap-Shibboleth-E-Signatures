<?php

namespace YaleREDCap\ShibbolethEsignatures;

class Authenticator
{
    private ShibbolethEsignatures $module;

    const ERROR_MESSAGE_AUTHENTICATION = 'ShibbolethEsignatures Authentication Error';
    const ENTITY_ID_SESSION_VARIABLE = 'ShibbolethEsignatures_EntityId';
    const ESIGN_REQUEST_TIMESTAMP_VARIABLE = 'ShibbolethEsignatures_Request_Timestamp';
    public function __construct(ShibbolethEsignatures $module)
    {
        $this->module = $module;
    }


    public static function getLoginUrl($redirectUrl = '') : string
    {
        global $auth_meth_global;
        $entityId               = Authenticator::getIdPEntityId();
        $handler                = $_SERVER['Shib-Handler'];

        if (empty($handler)) {
            return '';
        }

        $url = $handler . '/Login?forceAuthn=true&target=' . urlencode($redirectUrl);

        if ($auth_meth_global === 'shibboleth_table') {
            $url .= '&entityId=' . urlencode($entityId);
        }

        return $url;
    }



    private function logError(string $errorMessage) : void
    {
        $this->module->framework->log(self::ERROR_MESSAGE_AUTHENTICATION, [ 'error' => $errorMessage ]);
    }

    public static function getIdPEntityId() : string
    {
        // session_start();
        return $_SESSION[self::ENTITY_ID_SESSION_VARIABLE] ?? '';
    }

    public static function setIdPEntityId(string $entityId) : void
    {
        // session_start();
        $_SESSION[self::ENTITY_ID_SESSION_VARIABLE] = $entityId;
    }

    public static function setEsignRequestTimestamp() : int
    {
        // session_start();
        $requestInstant                                   = time();
        $_SESSION[self::ESIGN_REQUEST_TIMESTAMP_VARIABLE] = $requestInstant;
        return $requestInstant;
    }

    public static function getEsignRequestTimestamp() : int
    {
        // session_start();
        return $_SESSION[self::ESIGN_REQUEST_TIMESTAMP_VARIABLE] ?? -1;
    }

    public static function clearEsignRequestTimestamp() : void
    {
        // session_start();
        unset($_SESSION[self::ESIGN_REQUEST_TIMESTAMP_VARIABLE]);
    }

    public static function storeShibbolethInformation() : void
    {
        $entityId = self::getIdPEntityId();
        if (empty($entityId)) {
            return;
        }
        self::setIdPEntityId($entityId);
    }
}