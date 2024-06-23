<?php

namespace YaleREDCap\EntraIdAuthenticator;

class Utilities
{
    private $module;
    public function __construct(EntraIdAuthenticator $module)
    {
        $this->module = $module;
    }

    public static function getEdocFileContents($edocId)
    {
        if ( empty($edocId) ) {
            return;
        }
        $file     = \REDCap::getFile($edocId);
        $contents = $file[2];

        return 'data:' . $file[0] . ';base64,' . base64_encode($contents);
    }

    public static function curPageURL()
    {
        $pageURL = 'http';
        if ( isset($_SERVER["HTTPS"]) )
            if ( $_SERVER["HTTPS"] == "on" ) {
                $pageURL .= "s";
            }
        $pageURL .= "://";
        if ( $_SERVER["SERVER_PORT"] != "80" ) {
            $pageURL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
        } else {
            $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
        }
        $pageURLClean = filter_var($pageURL, FILTER_SANITIZE_URL);
        return $pageURLClean;
    }

    public static function stripQueryParameter($url, $param)
    {
        $parsed  = parse_url($url);
        $baseUrl = strtok($url, '?');
        if ( isset($parsed['query']) ) {
            parse_str($parsed['query'], $params);
            unset($params[$param]);
            $parsed = empty($params) ? '' : http_build_query($params);
            return $baseUrl . (empty($parsed) ? '' : '?') . $parsed;
        } else {
            return $url;
        }
    }

    public static function addQueryParameter(string $url, string $param, string $value = '')
    {
        $parsed  = parse_url($url);
        $baseUrl = strtok($url, '?');
        if ( isset($parsed['query']) ) {
            parse_str($parsed['query'], $params);
            $params[$param] = $value;
            $parsed         = http_build_query($params);
        } else {
            $parsed = http_build_query([ $param => $value ]);
        }
        return $baseUrl . (empty($parsed) ? '' : '?') . $parsed;
    }

    public static function inLoginFunction()
    {
        return sizeof(array_filter(debug_backtrace(), function ($value) {
            return $value['function'] == 'loginFunction';
        })) > 0;
    }

    public static function inAuthenticateFunction()
    {
        return sizeof(array_filter(debug_backtrace(), function ($value) {
            return $value['function'] == 'authenticate';
        })) > 0;
    }

    public static function needsModifiedLogin(string $page, EntraIdAuthenticator $module)
    {
        return $module->framework->getSystemSetting('custom-login-page-type') === "modified" &&
            !self::resettingPassword($page) &&
            !self::doingLocalLogin() &&
            Utilities::inLoginFunction() &&
            \ExternalModules\ExternalModules::getUsername() === null &&
            !\ExternalModules\ExternalModules::isNoAuth();
    }

    public static function doingLocalLogin()
    {
        return isset($_GET[EntraIdAuthenticator::AUTH_QUERY]) && $_GET[EntraIdAuthenticator::AUTH_QUERY] == EntraIdAuthenticator::LOCAL_AUTH;
    }

    public static function resettingPassword(string $page)
    {
        return (isset($_GET['action']) && $_GET['action'] == 'passwordreset') ||
            $page == 'Authentication/password_recovery.php' ||
            $page == 'Authentication/password_reset.php' ||
            $page == 'Profile/user_info_action.php';
    }

    public static function generateSiteId()
    {
        return bin2hex(random_bytes(16));
    }
}