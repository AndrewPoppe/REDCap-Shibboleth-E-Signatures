<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

/**
 * @property \ExternalModules\Framework $framework
 * @see Framework
 */

require_once 'YNHH_SAML_Authenticator.php';
require_once 'Yale_EntraID_Authenticator.php';

class YaleREDCapAuthenticator extends \ExternalModules\AbstractExternalModule
{

    static $CAS_AUTH = 'CAS_auth';
    static $YNHH_AUTH = 'YNHH_auth';
    static $ENTRAID_AUTH = 'EntraID_auth';

    public function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
    {
        // Normal Users
        if ( $action === 'eraseCasSession' ) {
            return $this->eraseCasSession();
        }

        // Admins only
        if ( !$this->framework->getUser()->isSuperUser() ) {
            throw new \Exception('Unauthorized');
        }
        if ( $action === 'isCasUser' ) {
            return $this->isCasUser($payload['username']);
        }
        if ( $action === 'getUserType' ) {
            return $this->getUserType($payload['username']);
        }
        if ( $action === 'convertTableUserToCasUser' ) {
            return $this->convertTableUserToCasUser($payload['username']);
        }
        if ( $action == 'convertCasUsertoTableUser' ) {
            return $this->convertCasUsertoTableUser($payload['username']);
        }
    }

    public function redcap_every_page_before_render($project_id = null)
    {
        $page = defined('PAGE') ? PAGE : null;
        if ( empty($page) ) {
            return;
        }

        // Handle E-Signature form action
        if ( $page === 'Locking/single_form_action.php' ) {
            if ( !isset($_POST['esign_action']) || $_POST['esign_action'] !== 'save' || !isset($_POST['username']) || !isset($_POST['cas_code']) ) {
                return;
            }
            if ( $_POST['cas_code'] !== $this->getCode($_POST['username']) ) {
                $this->log('CAS Login E-Signature: Error authenticating user');
                $this->exitAfterHook();
                return;
            }
            $this->setCode($_POST['username'], '');

            global $auth_meth_global;
            $auth_meth_global = 'none';
            return;
        }

        // If we're on the login page, inject the CAS login button
        if (
            $this->inLoginFunction() &&
            \ExternalModules\ExternalModules::getUsername() === null && 
            !\ExternalModules\ExternalModules::isNoAuth() && 
            !isset($_GET[self::$CAS_AUTH]) && 
            !isset($_GET[self::$YNHH_AUTH]) && 
            !isset($_GET[self::$ENTRAID_AUTH])
        ) {


            if ( (isset($_GET['action']) && $_GET['action'] == 'passwordreset') || $page == 'Authentication/password_recovery.php' ) {
                return;
            }
            if ( (isset($_GET['logintype']) && $_GET['logintype'] == 'locallogin') ) {
                return;
            }
            $this->showCustomLoginPage($this->curPageURL());
            $this->exitAfterHook();
            return;
        }

        // Already logged in to REDCap
        if ( (defined('USERID') && defined('USERID') !== '') || $this->framework->isAuthenticated() ) {
            if ( (isset($_GET['logintype']) && $_GET['logintype'] == 'locallogin') ) {
                $cleanUrl = $this->stripQueryParameter($this->curPageURL(), 'logintype');
                $this->redirectAfterHook($cleanUrl);
            }
            return;
        }

        // Only authenticate if we're asked to (but include the login page HTML if we're not logged in)
        if ( isset($_GET[self::$CAS_AUTH]) ) {
            $this->handleCasAuth($page);
        } elseif ( isset($_GET[self::$YNHH_AUTH]) ) {
            $this->handleYnhhAuth($page);
        } elseif ( isset($_GET[self::$ENTRAID_AUTH]) ) {
            $protocol      = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
            $curPageURL    = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            $this->handleEntraIDAuth($curPageURL);
        }

    }

    public function handleYnhhAuth($page)
    {
        if ( isset($_GET['authed']) ) {
            return;
        }

        $protocol      = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $curPageURL    = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $newUrl        = $this->addQueryParameter($curPageURL, 'authed', 'true');
        $authenticator = new YNHH_SAML_Authenticator('http://localhost:33810', $this->framework->getUrl('YNHH_SAML_ACS.php', true));

        // Perform login
        $authenticator->login($newUrl, [], false, true);
        // Check authentication status
        if ( $authenticator->isAuthenticated() ) {
            // User is authenticated, proceed with further actions
            $attributes = $authenticator->getAttributes();
            $this->log('authed', [ 'attributes' => json_encode($attributes, JSON_PRETTY_PRINT) ]);
            // Process user attributes as needed
        } else {
            // Authentication failed
            $this->log('no authed');
            echo "Authentication failed. Reason: " . $authenticator->getLastError();
        }

        // // Perform logout if needed
        // $authenticator->logout();

    }

    public function handleEntraIDAuth($url)
    {
        \Session::savecookie('PHPSESSID2', session_id(), 0, true);
        global $enable_user_allowlist, $homepage_contact, $homepage_contact_email, $lang;
        try {
            \Session::savecookie('entraid-yale-origin-url', $url, 0, true);
            
            $authenticator = new Yale_EntraID_Authenticator($this, session_id());
            if ( !isset($_GET["code"]) and !isset($_GET["error"]) ) {
                $authenticator->authenticate();
                return true;
            }
        } catch ( \Throwable $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error 1', [ 'error' => $e->getMessage() ]);
            session_unset();
            session_destroy();
            return false;
        }
    }

    public function loginEntraIDUser(array $userdata) {
        global $enable_user_allowlist, $homepage_contact, $homepage_contact_email, $lang;
        try {
            $userid = $userdata['netid'];
            if ( $userid === false ) {
                return false;
            }

            if ( $this->checkCASAffiliation($userid) === false ) {
                $this->framework->log('Yale REDCap Authenticator: User\'s affiliation not allowed', [ 'userid' => $userid ]);
                echo "You are not authorized to access this page. Please contact the administrator.";
                return false;
            }

            // Successful authentication
            $this->framework->log('Yale REDCap Authenticator: Auth Succeeded', [
                "EntraID NetID" => $userid
            ]);

            // Trigger login
            \Authentication::autoLogin($userid);

            // Update last login timestamp
            \Authentication::setUserLastLoginTimestamp($userid);

            // Log the login
            \Logging::logPageView("LOGIN_SUCCESS", $userid);

            // Handle account-related things.
            // If the user does not exist, try to fetch user details and create them.
            if ( !$this->userExists($userid) ) {
                // $userDetails = $this->fetchUserDetails($userid);
                if ( 
                    isset($userdata['user_firstname']) &&
                    isset($userdata['user_lastname']) &&
                    isset($userdata['user_email'])
                ){
                    $this->setUserDetails($userid, $userdata);
                }
                $this->setCasUser($userid);
            }
            // If user is a table-based user, convert to CAS user
            elseif ( \Authentication::isTableUser($userid) ) {
                $this->convertTableUserToCasUser($userid);
            }
            // otherwise just make sure they are logged as a CAS user
            else {
                $this->setCasUser($userid);
            }

            // 2. If user allowlist is not enabled, all CAS users are allowed.
            // Otherwise, if not in allowlist, then give them error page.
            if ( $enable_user_allowlist && !$this->inUserAllowlist($userid) ) {
                session_unset();
                session_destroy();
                $objHtmlPage = new \HtmlPage();
                $objHtmlPage->addExternalJS(APP_PATH_JS . "base.js");
                $objHtmlPage->addStylesheet("home.css", 'screen,print');
                $objHtmlPage->PrintHeader();
                print "<div class='red' style='margin:40px 0 20px;padding:20px;'>
                            {$lang['config_functions_78']} \"<b>$userid</b>\"{$lang['period']}
                            {$lang['config_functions_79']} <a href='mailto:$homepage_contact_email'>$homepage_contact</a>{$lang['period']}
                        </div>
                        <button onclick=\"window.location.href='" . APP_PATH_WEBROOT_FULL . "index.php?logout=1';\">Go back</button>";
                print '<div id="my_page_footer">' . \REDCap::getCopyright() . '</div>';
                return false;
            }
            return true;
        } catch ( \Throwable $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error 2', [ 'error' => $e->getMessage() ]);
            session_unset();
            session_destroy();
            return false;
        }
    }

    public function handleCasAuth($page)
    {
        global $enable_user_allowlist, $homepage_contact, $homepage_contact_email, $lang;
        try {
            $userid = $this->authenticate();
            if ( $userid === false ) {
                $this->exitAfterHook();
                return;
            }

            if ( $this->checkCASAffiliation($userid) === false ) {
                $this->framework->log('Yale REDCap Authenticator: User\'s affiliation not allowed', [ 'userid' => $userid ]);
                echo "You are not authorized to access this page. Please contact the administrator.";
                $this->exitAfterHook();
                return;
            }

            // Successful authentication
            $this->framework->log('Yale REDCap Authenticator: Auth Succeeded', [
                "CASAuthenticator_NetId" => $userid,
                "page"                   => $page
            ]);

            // Trigger login
            \Authentication::autoLogin($userid);

            // Update last login timestamp
            \Authentication::setUserLastLoginTimestamp($userid);

            // Log the login
            \Logging::logPageView("LOGIN_SUCCESS", $userid);

            // Handle account-related things.
            // If the user does not exist, try to fetch user details and create them.
            if ( !$this->userExists($userid) ) {
                $userDetails = $this->fetchUserDetails($userid);
                if ( $userDetails ) {
                    $this->setUserDetails($userid, $userDetails);
                }
                $this->setCasUser($userid);
            }
            // If user is a table-based user, convert to CAS user
            elseif ( \Authentication::isTableUser($userid) ) {
                $this->convertTableUserToCasUser($userid);
            }
            // otherwise just make sure they are logged as a CAS user
            else {
                $this->setCasUser($userid);
            }

            // 2. If user allowlist is not enabled, all CAS users are allowed.
            // Otherwise, if not in allowlist, then give them error page.
            if ( $enable_user_allowlist && !$this->inUserAllowlist($userid) ) {
                session_unset();
                session_destroy();
                $objHtmlPage = new \HtmlPage();
                $objHtmlPage->addExternalJS(APP_PATH_JS . "base.js");
                $objHtmlPage->addStylesheet("home.css", 'screen,print');
                $objHtmlPage->PrintHeader();
                print "<div class='red' style='margin:40px 0 20px;padding:20px;'>
                            {$lang['config_functions_78']} \"<b>$userid</b>\"{$lang['period']}
                            {$lang['config_functions_79']} <a href='mailto:$homepage_contact_email'>$homepage_contact</a>{$lang['period']}
                        </div>
                        <button onclick=\"window.location.href='" . APP_PATH_WEBROOT_FULL . "index.php?logout=1';\">Go back</button>";
                print '<div id="my_page_footer">' . \REDCap::getCopyright() . '</div>';
                $this->framework->exitAfterHook();
                return;
            }

            // url to redirect to after login
            $redirect = $this->curPageURL();
            // strip the "CAS_auth" parameter from the URL
            $redirectStripped = $this->stripQueryParameter($redirect, self::$CAS_AUTH);
            // Redirect to the page we were on
            $this->redirectAfterHook($redirectStripped);
            return;
        } catch ( \CAS_GracefullTerminationException $e ) {
            if ( $e->getCode() !== 0 ) {
                $this->framework->log('Yale REDCap Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
                session_unset();
                session_destroy();
                $this->exitAfterHook();
                return;
            }
        } catch ( \Throwable $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error 3', [ 'error' => $e->getMessage() ]);
            session_unset();
            session_destroy();
            $this->exitAfterHook();
            return;
        }
    }

    public function redcap_every_page_top($project_id)
    {
        $page = defined('PAGE') ? PAGE : null;
        if ( empty($page) ) {
            return;
        }

        // If we are on the Browse Users page, add CAS-User information if applicable 
        if ( $page === 'ControlCenter/view_users.php' ) {
            $this->addCasInfoToBrowseUsersTable();
        }
    }

    public function redcap_data_entry_form()
    {
        $user = $this->framework->getUser();
        if ( !$this->isCasUser($user->getUsername()) ) {
            return;
        }
        $this->framework->initializeJavascriptModuleObject();
        ?>
        <script>
            $(document).ready(function () {
                const authenticator = <?= $this->getJavascriptModuleObjectName() ?>;
                var numLogins = 0;
                var esign_action_global;
                const saveLockingOrig = saveLocking;
                window.addEventListener('message', (event) => {
                    if (event.origin !== window.location.origin) {
                        return;
                    }
                    const action = 'lock';
                    $.post(app_path_webroot + "Locking/single_form_action.php?pid=" + pid, {
                        auto: getParameterByName('auto'),
                        instance: getParameterByName('instance'),
                        esign_action: esign_action_global,
                        event_id: event_id,
                        action: action,
                        username: event.data.username,
                        record: getParameterByName('id'),
                        form_name: getParameterByName('page'),
                        cas_code: event.data.code
                    }, function (data) {
                        if (data != "") {
                            numLogins = 0;
                            if (auto_inc_set && getParameterByName('auto') == '1' && isinteger(data.replace(
                                '-', ''))) {
                                $('#form :input[name="' + table_pk + '"], #form :input[name="__old_id__"]')
                                    .val(data);
                            }
                            formSubmitDataEntry();
                        } else {
                            numLogins++;
                            esignFail(numLogins);
                        }
                    });
                });
                saveLocking = function (lock_action, esign_action) {
                    if (esign_action !== 'save' || lock_action !== 1) {
                        saveLockingOrig(lock_action, esign_action);
                        return;
                    }
                    esign_action_global = esign_action;
                    authenticator.ajax('eraseCasSession', {}).then(() => {
                        const url = '<?= $this->getUrl('cas_login.php') ?> ';
                        window.open(url, null, 'popup=true,innerWidth=500,innerHeight=700');
                    });
                }
            });
        </script>
        <?php
    }

    private function getLoginButtonSettings()
    {
        return [
            'casLoginButtonBackgroundColor'        => $this->framework->getSystemSetting('cas-login-button-background-color') ?? 'transparent',//'#00356b',
            'casLoginButtonBackgroundColorHover'   => $this->framework->getSystemSetting('cas-login-button-background-color-hover') ?? 'transparent',//'#286dc0',
            'casLoginButtonText'                   => $this->framework->getSystemSetting('cas-login-button-text') ?? 'Yale University',
            'casLoginButtonLogo'                   => $this->framework->getSystemSetting('cas-login-button-logo') ?? $this->framework->getUrl('assets/images/YU.png', true, true),//'<i class="fas fa-sign-in-alt"></i>',
            'localLoginButtonBackgroundColor'      => $this->framework->getSystemSetting('local-login-button-background-color') ?? 'transparent',//'#00a9e0',
            'localLoginButtonBackgroundColorHover' => $this->framework->getSystemSetting('local-login-button-background-color-hover') ?? 'transparent',//'#32bae6',
            'localLoginButtonText'                 => $this->framework->getSystemSetting('local-login-button-text') ?? 'Yale New Haven Health',
            'localLoginButtonLogo'                 => $this->framework->getSystemSetting('local-login-button-logo') ?? $this->framework->getUrl('assets/images/YNHH.png', true, true),//'<i class="fas fa-sign-in-alt"></i>',
        ];
    }

    private function showCustomLoginPage(string $redirect)
    {
        $loginButtonSettings = $this->getLoginButtonSettings();
        $backgroundUrl       = $this->framework->getUrl('assets/images/New_Haven_1.jpg');
        ?>
        <!DOCTYPE html>
        <html lang="en">

        <head>
            <link rel="preload" href="<?= $backgroundUrl ?>" as="image">
        </head>
        <?php
        $objHtmlPage = new \HtmlPage();
        $objHtmlPage->PrintHeader(false);
        ?>
        <style>
            .btn-cas {
                background-color:
                    <?= $loginButtonSettings['casLoginButtonBackgroundColor'] ?>;
                background-image: url('<?= $loginButtonSettings['casLoginButtonLogo'] ?>');
                width: auto;
            }

            .btn-cas:hover,
            .btn-cas:focus,
            .btn-cas:active,
            .btn-cas.btn-active,
            .btn-cas:active:focus,
            .btn-cas:active:hover {
                color: #fff !important;
                background-color:
                    <?= $loginButtonSettings['casLoginButtonBackgroundColorHover'] ?> !important;
                border: 1px solid transparent;
            }

            .btn-login-original {
                background-color:
                    <?= $loginButtonSettings['localLoginButtonBackgroundColor'] ?>;
                background-image: url('<?= $loginButtonSettings['localLoginButtonLogo'] ?>');
                width: auto;
            }

            .btn-login-original:hover,
            .btn-login-original:focus,
            .btn-login-original:active,
            .btn-login-original.btn-active,
            .btn-login-original:active:focus,
            .btn-login-original:active:hover {
                color: #fff !important;
                background-color:
                    <?= $loginButtonSettings['localLoginButtonBackgroundColorHover'] ?> !important;
                border: 1px solid transparent !important;
            }

            .btn-login:hover,
            .btn-login:hover:active,
            .btn-login.btn-active:hover,
            .btn-login:focus {
                outline: 1px solid #4ca2ff !important;
            }

            .btn-login {
                background-size: contain;
                background-repeat: no-repeat;
                background-position: center;
                max-width: 350px;
                min-width: 250px;
                height: 50px;
                color: #fff;
                border: 1px solid transparent;
            }

            #rc-login-form {
                display: none;
            }

            #login-card {
                border-radius: 0;
            }

            .login-option {
                cursor: pointer;
                border-radius: 0 !important;
            }

            .login-option:hover {
                background-color: #dddddd !important;
            }

            #login-card {
                position: absolute;
                width: 502px;
                height: auto;
                margin: 0 auto;
                top: 125px;
                left: 50%;
                margin-left: -250px;
            }

            #container,
            #pagecontainer {
                background-color: transparent !important;
            }

            body {
                background-repeat: no-repeat !important;
                background-attachment: fixed !important;
                background-size: cover !important;
            }

            .login-options {
                left: 50%;
                margin-left: -37.5%;
                width: 75%;
                border-radius: 0 !important;
            }

            .login-logo {
                width: 100%;
            }

            div#working {
                top: 50% !important;
            }

            #my_page_footer a {
                text-decoration: none;
                color: inherit;
            }
        </style>

        <body background="<?= $backgroundUrl ?>">
            <?php

            global $login_logo, $institution, $login_custom_text, $homepage_announcement, $homepage_announcement_login, $homepage_contact, $homepage_contact_email;

            // Show custom login text (optional)
            if ( trim($login_custom_text) != "" ) {
                print "<div style='border:1px solid #ccc;background-color:#f5f5f5;margin:15px 10px 15px 0;padding:10px;'>" . nl2br(decode_filter_tags($login_custom_text)) . "</div>";
            }

            // Show custom homepage announcement text (optional)
            if ( trim($homepage_announcement) != "" && $homepage_announcement_login == '1' ) {
                print \RCView::div(array( 'style' => 'margin-bottom:10px;' ), nl2br(decode_filter_tags($homepage_announcement)));
                $hide_homepage_announcement = true; // Set this so that it's not displayed elsewhere on the page
            }
            ?>
            <div class="container text-center">
                <div class="row align-items-center">
                    <div class="col">
                        <div class="card" id="login-card">
                            <img src="<?= APP_PATH_IMAGES . 'redcap-logo-large.png' ?>" class="w-50 m-4 align-self-center">
                            <?php if ( trim($login_logo) ) { ?>
                                <img src="<?= $login_logo ?>" class="w-50 align-self-center m-3"
                                    title="<?= js_escape2(strip_tags(label_decode($institution))) ?>"
                                    alt="<?= js_escape2(strip_tags(label_decode($institution))) ?>">
                            <?php } ?>
                            <h4>
                                <?= \RCView::tt("config_functions_45") ?>
                            </h4>
                            <div class="card-body rounded-0">
                                <div class="card align-self-center text-center mb-2 login-options rounded-0">
                                    <ul class="list-group list-group-flush">
                                        <li class="list-group-item list-group-item-action login-option"
                                            onclick="showProgress(1);window.location.href='<?= $this->addQueryParameter($redirect, self::$ENTRAID_AUTH, '1') ?>';">
                                            <img src="<?= $this->framework->getUrl('assets/images/YU.png') ?>"
                                                class="login-logo">
                                        </li>
                                        <li class="list-group-item list-group-item-action login-option"
                                            onclick="showProgress(1);window.location.href='<?= $this->addQueryParameter($redirect, self::$YNHH_AUTH, '1') ?>';">
                                            <img src="<?= $this->framework->getUrl('assets/images/YNHH.png') ?>"
                                                class="login-logo">
                                        </li>
                                    </ul>
                                </div>
                                <a href="<?= $this->addQueryParameter($this->curPageURL(), 'logintype', 'locallogin') ?>"
                                    class="text-primary">
                                    Local login
                                </a>
                                <div id="my_page_footer" class="text-secondary mt-4">
                                    <?= \REDCap::getCopyright() ?>
                                    <br>
                                    <span><a href="https://campusphotos.yale.edu/" tabindex="-1" target="_blank"
                                            rel="noopener noreferrer">Image</a> - &copy;
                                        <?= date("Y") ?> Yale University
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php
    }

    private function curPageURL()
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
        return $pageURL;
    }

    public function stripQueryParameter($url, $param)
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

    public function addQueryParameter(string $url, string $param, string $value = '')
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

    private function convertTableUserToCasUser(string $userid)
    {
        if ( empty($userid) ) {
            return;
        }
        try {
            $SQL   = 'DELETE FROM redcap_auth WHERE username = ?';
            $query = $this->framework->query($SQL, [ $userid ]);
            $this->setCasUser($userid);
            return;
        } catch ( \Exception $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error converting table user to CAS user', [ 'error' => $e->getMessage() ]);
            return;
        }
    }

    private function convertCasUsertoTableUser(string $userid)
    {
        if ( empty($userid) ) {
            return;
        }
        try {
            $SQL   = "INSERT INTO redcap_auth (username) VALUES (?)";
            $query = $this->framework->query($SQL, [ $userid ]);
            \Authentication::resetPasswordSendEmail($userid);
            $this->setCasUser($userid, false);
            return;
        } catch ( \Exception $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error converting CAS user to table user', [ 'error' => $e->getMessage() ]);
            return;
        }
    }

    /**
     * @param string $userid
     * @return bool
     */
    private function inUserAllowlist(string $userid)
    {
        $SQL = "SELECT 1 FROM redcap_user_allowlist WHERE username = ?";
        $q   = $this->framework->query($SQL, [ $userid ]);
        return $q->fetch_assoc() !== null;
    }

    private function handleLogout()
    {
        if ( isset($_GET['logout']) && $_GET['logout'] ) {
            \phpCAS::logoutWithUrl(APP_PATH_WEBROOT_FULL);
        }
    }

    public function initializeCas()
    {
        //require_once __DIR__ . '/vendor/apereo/phpcas/CAS.php';
        require_once __DIR__ . '/vendor/autoload.php';
        if ( \phpCAS::isInitialized() ) {
            return true;
        }
        try {

            $cas_host                = $this->getSystemSetting("cas-host");
            $cas_context             = $this->getSystemSetting("cas-context");
            $cas_port                = (int) $this->getSystemSetting("cas-port");
            $cas_server_ca_cert_id   = $this->getSystemSetting("cas-server-ca-cert-pem");
            $cas_server_ca_cert_path = empty($cas_server_ca_cert_id) ? $this->getSafePath('cacert.pem') : $this->getFile($cas_server_ca_cert_id);
            $server_force_https      = $this->getSystemSetting("server-force-https");
            $service_base_url        = (SSL ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'];//APP_PATH_WEBROOT_FULL;

            // Enable https fix
            if ( $server_force_https == 1 ) {
                $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
                $_SERVER['HTTP_X_FORWARDED_PORT']  = 443;
                $_SERVER['HTTPS']                  = 'on';
                $_SERVER['SERVER_PORT']            = 443;
            }

            // Initialize phpCAS
            \phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context, $service_base_url, false);

            // Set the CA certificate that is the issuer of the cert
            // on the CAS server
            \phpCAS::setCasServerCACert($cas_server_ca_cert_path);

            // Don't exit, let me handle instead
            \CAS_GracefullTerminationException::throwInsteadOfExiting();
            return true;
        } catch ( \Throwable $e ) {
            $this->log('Yale REDCap Authenticator: Error initializing CAS', [ 'error' => $e->getMessage() ]);
            return false;
        }
    }

    /**
     * Initiate CAS authentication
     * 
     * 
     * @return string|boolean username of authenticated user (false if not authenticated)
     */
    public function authenticate()
    {
        try {

            $initialized = $this->initializeCas();
            if ( $initialized === false ) {
                $this->framework->log('Yale REDCap Authenticator: Error initializing CAS');
                throw new \Exception('Error initializing CAS');
            }

            // force CAS authentication
            \phpCAS::forceAuthentication();

            // Return authenticated username
            return \phpCAS::getUser();
        } catch ( \CAS_GracefullTerminationException $e ) {
            if ( $e->getCode() !== 0 ) {
                $this->framework->log('Yale REDCap Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
            }
            return false;
        } catch ( \Throwable $e ) {
            $this->framework->log('CAS Authenticator: Error authenticating', [ 'errorMessage' => $e->getMessage(), 'error' => json_encode($e, JSON_PRETTY_PRINT) ]);
            return false;
        }
    }

    public function renewAuthentication()
    {
        try {
            $initialized = $this->initializeCas();
            if ( !$initialized ) {
                $this->framework->log('CAS Login E-Signature: Error initializing CAS');
                throw new \Exception('Error initializing CAS');
            }

            $cas_url = \phpCAS::getServerLoginURL() . '%26cas_authed%3Dtrue&renew=true';
            \phpCAS::setServerLoginURL($cas_url);
            \phpCAS::forceAuthentication();
        } catch ( \CAS_GracefullTerminationException $e ) {
            if ( $e->getCode() !== 0 ) {
                $this->framework->log('CAS Login E-Signature: Error getting code', [ 'error' => $e->getMessage() ]);
            }
            return false;
        } catch ( \Throwable $e ) {
            $this->framework->log('CAS Login E-Signature: Error authenticating', [ 'error' => json_encode($e, JSON_PRETTY_PRINT) ]);
            return false;
        }
    }


    /**
     * Get url to file with provided edoc ID.
     * 
     * @param string $edocId ID of the file to find
     * 
     * @return string path to file in edoc folder
     */
    private function getFile(string $edocId)
    {
        $filePath = "";
        if ( $edocId === null ) {
            return $filePath;
        }
        $result   = $this->query('SELECT stored_name FROM redcap_edocs_metadata WHERE doc_id = ?', $edocId);
        $filename = $result->fetch_assoc()["stored_name"];
        if ( defined('EDOC_PATH') ) {
            $filePath = $this->framework->getSafePath(EDOC_PATH . $filename, EDOC_PATH);
        }
        return $filePath;
    }


    private function casLog($message, $params = [], $record = null, $event = null)
    {
        $doProjectLogging = $this->getProjectSetting('logging');
        if ( $doProjectLogging ) {
            $changes = "";
            foreach ( $params as $label => $value ) {
                $changes .= $label . ": " . $value . "\n";
            }
            \REDCap::logEvent(
                $message,
                $changes,
                null,
                $record,
                $event
            );
        }
        $this->framework->log($message, $params);
    }

    private function jwt_request(string $url, string $token)
    {
        $result = null;
        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $authorization = "Authorization: Basic " . $token;
            $authheader    = array( 'Content-Type: application/json', $authorization );
            curl_setopt($ch, CURLOPT_HTTPHEADER, $authheader);
            $result = curl_exec($ch);
            curl_close($ch);
            $response = preg_replace("/(<\/?)(\w+):([^>]*>)/", "$1$2$3", $result);
            $xml      = new \SimpleXMLElement($response);
            $result   = json_decode(json_encode((array) $xml), TRUE);
        } catch ( \Throwable $e ) {
            $this->framework->log('CAS Authenticator: Error', [ 'error' => $e->getMessage() ]);
        } finally {
            return $result;
        }
    }

    private function fetchUserDetails(string $userid)
    {
        $url   = $this->getSystemSetting('cas-user-details-url');
        $token = $this->getSystemSetting('cas-user-details-token');
        if ( empty($url) || empty($token) ) {
            return null;
        }
        $url      = str_replace('{userid}', $userid, $url);
        $response = $this->jwt_request($url, $token);
        return $this->parseUserDetailsResponse($response);
    }

    private function parseUserDetailsResponse($response)
    {
        if ( empty($response) ) {
            return null;
        }
        $userDetails = [];
        try {
            $userDetails['user_firstname'] = $response['Person']['Names']['ReportingNm']['First'];
            $userDetails['user_lastname']  = $response['Person']['Names']['ReportingNm']['Last'];
            $userDetails['user_email']     = $response['Person']['Contacts']['Email'];
            $userDetails['affiliation']    = $response['Person']['Affiliations']['PEDUAffiliation'];
        } catch ( \Throwable $e ) {
            $this->framework->log('CAS Authenticator: Error parsing user details response', [ 'error' => $e->getMessage() ]);
        } finally {
            return $userDetails;
        }
    }

    private function setUserDetails($userid, $details)
    {
        if ( $this->userExists($userid) ) {
            $this->updateUserDetails($userid, $details);
        } else {
            $this->insertUserDetails($userid, $details);
        }
    }

    private function userExists($userid)
    {
        $SQL = 'SELECT 1 FROM redcap_user_information WHERE username = ?';
        $q   = $this->framework->query($SQL, [ $userid ]);
        return $q->fetch_assoc() !== null;
    }

    private function updateUserDetails($userid, $details)
    {
        try {
            $SQL    = 'UPDATE redcap_user_information SET user_firstname = ?, user_lastname = ?, user_email = ? WHERE username = ?';
            $PARAMS = [ $details['user_firstname'], $details['user_lastname'], $details['user_email'], $userid ];
            $query  = $this->createQuery();
            $query->add($SQL, $PARAMS);
            $query->execute();
            return $query->affected_rows;
        } catch ( \Exception $e ) {
            $this->framework->log('CAS Authenticator: Error updating user details', [ 'error' => $e->getMessage() ]);
        }
    }

    private function insertUserDetails($userid, $details)
    {
        try {
            $SQL    = 'INSERT INTO redcap_user_information (username, user_firstname, user_lastname, user_email, user_creation) VALUES (?, ?, ?, ?, ?)';
            $PARAMS = [ $userid, $details['user_firstname'], $details['user_lastname'], $details['user_email'], NOW ];
            $query  = $this->createQuery();
            $query->add($SQL, $PARAMS);
            $query->execute();
            return $query->affected_rows;
        } catch ( \Exception $e ) {
            $this->framework->log('CAS Authenticator: Error inserting user details', [ 'error' => $e->getMessage() ]);
        }
    }

    public function createCode()
    {
        return uniqid('cas_', true);
    }

    public function setCode($username, $code)
    {
        $this->framework->setSystemSetting('cas-code-' . $username, $code);
    }
    public function getCode($username)
    {
        return $this->framework->getSystemSetting('cas-code-' . $username);
    }

    public function isCasUser($username)
    {
        return !\Authentication::isTableUser($username) && $this->framework->getSystemSetting('cas-user-' . $username) === true;
    }

    public function getUserType($username)
    {
        if ( $this->isCasUser($username) ) {
            return 'CAS';
        }
        if ( $this->inUserAllowlist($username) ) {
            return 'allowlist';
        }
        if ( \Authentication::isTableUser($username) ) {
            return 'table';
        }
        return 'unknown';
    }

    public function setCasUser($userid, bool $value = true)
    {
        $this->framework->setSystemSetting('cas-user-' . $userid, $value);
    }

    public function eraseCasSession()
    {
        $this->initializeCas();
        unset($_SESSION[\phpCAS::getCasClient()::PHPCAS_SESSION_PREFIX]);
        return;
    }

    private function addCasInfoToBrowseUsersTable()
    {

        $this->framework->initializeJavascriptModuleObject();

        parse_str($_SERVER['QUERY_STRING'], $query);
        if ( isset($query['username']) ) {
            $userid   = $query['username'];
            $userType = $this->getUserType($userid);
        }

        ?>
            <script>
                var authenticator = <?= $this->getJavascriptModuleObjectName() ?>;

                function convertTableUserToCasUser() {
                    const username = $('#user_search').val();
                    Swal.fire({
                        title: "Are you sure you want to convert this table-based user to a CAS user?",
                        icon: "warning",
                        showCancelButton: true,
                        confirmButtonText: "Convert to CAS User"
                    }).then((result) => {
                        if (result.isConfirmed) {
                            authenticator.ajax('convertTableUserToCasUser', {
                                username: username
                            }).then(() => {
                                location.reload();
                            });
                        }
                    });
                }

                function convertCasUsertoTableUser() {
                    const username = $('#user_search').val();
                    Swal.fire({
                        title: "Are you sure you want to convert this CAS user to a table-based user?",
                        icon: "warning",
                        showCancelButton: true,
                        confirmButtonText: "Convert to Table User"
                    }).then((result) => {
                        if (result.isConfirmed) {
                            authenticator.ajax('convertCasUsertoTableUser', {
                                username: username
                            }).then(() => {
                                location.reload();
                            });
                        }
                    });
                }

                function addTableRow(userType) {
                    console.log(userType);
                    let casUserText = '';
                    switch (userType) {
                        case 'CAS':
                            casUserText =
                                `<strong>${userType}</strong> <input type="button" style="font-size:11px" onclick="convertCasUsertoTableUser()" value="Convert to Table User">`;
                            break;
                        case 'allowlist':
                            casUserText = `<strong>${userType}</strong>`;
                            break;
                        case 'table':
                            casUserText =
                                `<strong>${userType}</strong> <input type="button" style="font-size:11px" onclick="convertTableUserToCasUser()" value="Convert to CAS User">`;
                            break;
                        default:
                            casUserText = `<strong>${userType}</strong>`;
                            break;
                    }
                    console.log($('#indv_user_info'));
                    $('#indv_user_info').append('<tr id="userTypeRow"><td class="data2">User type</td><td class="data2">' +
                        casUserText + '</td></tr>');
                }

                view_user = function (username) {
                    if (username.length < 1) return;
                    $('#view_user_progress').css({
                        'visibility': 'visible'
                    });
                    $('#user_search_btn').prop('disabled', true);
                    $('#user_search').prop('disabled', true);
                    $.get(app_path_webroot + 'ControlCenter/user_controls_ajax.php', {
                        user_view: 'view_user',
                        view: 'user_controls',
                        username: username
                    },
                        function (data) {
                            authenticator.ajax('getUserType', {
                                username: username
                            }).then((userType) => {
                                $('#view_user_div').html(data);
                                addTableRow(userType);
                                enableUserSearch();
                                highlightTable('indv_user_info', 1000);
                            });
                        }
                    );
                }

                <?php if ( isset($userid) ) { ?>
                    window.requestAnimationFrame(() => {
                        addTableRow('<?= $userType ?>')
                    });
                <?php } ?>

                $(document).ready(function () {
                    <?php if ( isset($userid) ) { ?>
                        if (!$('#userTypeRow').length) {
                            view_user('<?= $userid ?>');
                        }

                    <?php } ?>
                });
            </script>
            <?php
    }

    public function inLoginFunction()
    {
        return sizeof(array_filter(debug_backtrace(), function ($value) {
            return $value['function'] == 'loginFunction';
        })) > 0;
    }

    public function shouldShowCustomLogin()
    {
        return !(isset($_GET['logintype']) && $_GET['logintype'] == 'locallogin') &&
            \ExternalModules\ExternalModules::getUsername() === null &&
            !\ExternalModules\ExternalModules::isNoAuth();
    }

    public function checkCASAuth()
    {
        $isAuthed = false;
        try {
            $this->initializeCas();
            if ( \phpCAS::checkAuthentication() ) {
                $isAuthed = true;
            }
        } catch ( \CAS_GracefullTerminationException $e ) {
            if ( $e->getCode() !== 0 ) {
                $this->framework->log('Yale REDCap Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
            }
            return false;
        } catch ( \Throwable $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error checking CAS auth', [ 'error' => $e->getMessage() ]);
        } finally {
            return $isAuthed;
        }
    }
    public function checkYNHHAuth()
    {
        $isAuthed = false;
        try {
            if ( isset($_GET['authed']) ) {
                return;
            }

            $protocol      = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
            $curPageURL    = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            $newUrl        = $this->addQueryParameter($curPageURL, 'authed', 'true');
            $authenticator = new YNHH_SAML_Authenticator('http://localhost:33810', $this->framework->getUrl('YNHH_SAML_ACS.php', true));

            // Perform login

            // // $this->log('test', ['isAuthenticated' => $authenticator->]);
            $authenticator->login(
                $newUrl,
                [],
                false,
                true
            );
            $isAuthed = $authenticator->isAuthenticated();

        } catch ( \Throwable $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error checking YNHH auth', [ 'error' => $e->getMessage() ]);
        } finally {
            return $isAuthed;
        }
    }

    public function checkCASAffiliation($userid)
    {
        if ( !$this->framework->getSystemSetting('cas-check-affiliation') ) {
            return true;
        }
        $allowedAffiliations   = $this->cleanArray($this->framework->getSystemSetting('cas-allowed-affiliations'));
        $forbiddenAffiliations = $this->cleanArray($this->framework->getSystemSetting('cas-forbidden-affiliations'));

        if ( !empty($allowedAffiliations) || !empty($forbiddenAffiliations) ) {
            $userDetails = $this->fetchUserDetails($userid);
            if ( empty($userDetails) ) {
                return false;
            }
            $affiliation = $userDetails['affiliation'];
            if ( !empty($allowedAffiliations) ) {
                return in_array($affiliation, $allowedAffiliations);
            }
            if ( !empty($forbiddenAffiliations) ) {
                return !in_array($affiliation, $forbiddenAffiliations);
            }
        }
        return true;
    }

    private function cleanArray($array)
    {
        return array_map('upper', array_map('trim', array_filter($array, function ($value) {
            return !empty ($value) && $value !== 'null';
        })));
    }

    private function setUserCreationTimestamp($userid)
    {
        try {
            $SQL = "UPDATE redcap_user_information SET user_creation = ? WHERE username = ?";
            $this->framework->query($SQL, [ NOW, $userid ]);
        } catch ( \Exception $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error setting user creation timestamp', [ 'error' => $e->getMessage() ]);
        }
    }

    /**
     * Just until my minimum RC version is >= 13.10.1
     * @param mixed $url
     * @param mixed $forceJS
     * @return void
     */
    public function redirectAfterHook($url, $forceJS = false)
    {
        // If contents already output, use javascript to redirect instead
        if ( headers_sent() || $forceJS ) {
            $url = \ExternalModules\ExternalModules::escape($url);
            echo "<script type=\"text/javascript\">window.location.href=\"$url\";</script>";
        }
        // Redirect using PHP
        else {
            header("Location: $url");
        }

        \ExternalModules\ExternalModules::exitAfterHook();
    }
}