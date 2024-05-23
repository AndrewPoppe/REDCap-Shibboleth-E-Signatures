<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

/**
 * @property \ExternalModules\Framework $framework
 * @see Framework
 */

require_once 'classes/YNHH_SAML_Authenticator.php';
require_once 'classes/Yale_EntraID_Authenticator.php';
require_once 'classes/ESignatureHandler.php';

class YaleREDCapAuthenticator extends \ExternalModules\AbstractExternalModule
{

    static $AUTH_QUERY = 'authtype';
    static $YNHH_AUTH = 'ynhh';
    static $YALE_AUTH = 'yale';
    static $LOCAL_AUTH = 'local';
    static $ENTRAID_URL_COOKIE = 'entraid-origin-url';
    static $ENTRAID_SESSION_ID_COOKIE = 'entraid-session-id';

    public function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
    {
        // Admins only
        if ( !$this->framework->getUser()->isSuperUser() ) {
            throw new \Exception('Unauthorized');
        }
        if ( $action === 'getUserType' ) {
            return $this->getUserType($payload['username']);
        }
        if ( $action === 'convertTableUserToYaleUser' ) {
            return $this->convertTableUserToYaleUser($payload['username']);
        }
        if ( $action == 'convertYaleUsertoTableUser' ) {
            return $this->convertYaleUsertoTableUser($payload['username']);
        }
    }

    public function redcap_every_page_before_render($project_id = null)
    {
        try {
            $page = defined('PAGE') ? PAGE : null;
            if ( empty($page) ) {
                return;
            }

            if ( isset($_GET['logout']) && $_GET['logout']) {
                \Authentication::checkLogout();
                return;
            }

            // Handle E-Signature form action
            if ( $page === 'Locking/single_form_action.php' ) {
                $esignatureHandler = new ESignatureHandler($this);
                $esignatureHandler->handleRequest($_POST);
                return;
            }

            // Already logged in to REDCap
            if ( $this->isLoggedIntoREDCap() ) {
                if ( $this->doingLocalLogin() ) {
                    $cleanUrl = $this->stripQueryParameter($this->curPageURL(), self::$AUTH_QUERY);
                    $this->redirectAfterHook($cleanUrl);
                }
                return;
            }
            
            // Only authenticate if we're asked to
            if ( $this->doingYNHHAuth() ) {
                $this->handleYnhhAuth($page);
            } elseif ( $this->doingYaleAuth() ) {
                $this->handleEntraIDAuth($this->curPageURL());
            }
            
            // Inject the custom login page 
            if ( $this->needsCustomLogin($page) ) {
                $this->showCustomLoginPage($this->curPageURL());
                $this->exitAfterHook();
                return;
            }
        } catch ( \Throwable $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error', [ 'error' => $e->getMessage() ]);
        }

    }

    public function handleYnhhAuth($page)
    {
        if ( isset($_GET['authed']) ) {
            return;
        }

        $curPageURL    = $this->curPageURL();
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
    }

    public function handleEntraIDAuth($url)
    {
        try {
            $session_id = session_id();
            \Session::savecookie(self::$ENTRAID_SESSION_ID_COOKIE, $session_id, 0, true);
            \Session::savecookie(self::$ENTRAID_URL_COOKIE, $url, 0, true);
            $authenticator = new Yale_EntraID_Authenticator($this, $session_id);
            $authenticator->authenticate();
            return true;
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

            // Check if user exists in REDCap, if not and if we are not supposed to create them, leave
            if (!$this->userExists($userid) && !$this->framework->getSystemSetting('create-new-users-on-login') == 1)
            {
                exit('User does not exist in REDCap. Please contact your administrator.');
            }

            // Successful authentication
            $this->framework->log('Yale REDCap Authenticator: Auth Succeeded', [
                "EntraID NetID" => $userid
            ]);

            // Trigger login
            \Authentication::autoLogin($userid);
            $_SESSION['yale_entraid_id'] = $userdata['id'];

            // Update last login timestamp
            \Authentication::setUserLastLoginTimestamp($userid);

            // Log the login
            \Logging::logPageView("LOGIN_SUCCESS", $userid);

            // Handle account-related things.
            // If the user does not exist, create them.
            if ( !$this->userExists($userid) ) {
                if ( 
                    isset($userdata['user_firstname']) &&
                    isset($userdata['user_lastname']) &&
                    isset($userdata['user_email'])
                ){
                    $this->setUserDetails($userid, $userdata);
                }
                $this->setYaleUser($userid);
            }
            // If user is a table-based user, convert to Yale user
            elseif ( \Authentication::isTableUser($userid) && $this->framework->getSystemSetting('convert-table-user-to-yale-user') == 1) {
                $this->convertTableUserToYaleUser($userid);
            }
            // otherwise just make sure they are logged as a Yale user
            elseif ( !\Authentication::isTableUser($userid) ) {
                $this->setYaleUser($userid);
            }

            // 2. If user allowlist is not enabled, all Yale users are allowed.
            // Otherwise, if not in allowlist, then give them an error page.
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

    public function redcap_every_page_top($project_id)
    {
        $page = defined('PAGE') ? PAGE : null;
        if ( empty($page) ) {
            return;
        }

        // To enable SLO
        $this->addReplaceLogoutLinkScript();

        // Yale-User information if applicable 
        $this->addYaleInfoToBrowseUsersTable($page);
    }

    public function redcap_data_entry_form()
    {
        $user = $this->framework->getUser();
        if ( !$this->isYaleUser($user->getUsername()) || !$this->framework->getSystemSetting('custom-login-page-enabled') == 1) {
            return;
        }
        $esignatureHandler = new ESignatureHandler($this);
        $esignatureHandler->addEsignatureScript();
    }

    private function getLoginButtonSettings()
    {
        return [
            'yaleLoginButtonBackgroundColor'        => $this->framework->getSystemSetting('yale-login-button-background-color') ?? 'transparent',//'#00356b',
            'yaleLoginButtonBackgroundColorHover'   => $this->framework->getSystemSetting('yale-login-button-background-color-hover') ?? 'transparent',//'#286dc0',
            'yaleLoginButtonText'                   => $this->framework->getSystemSetting('yale-login-button-text') ?? 'Yale University',
            'yaleLoginButtonLogo'                   => $this->getEdocFileContents($this->framework->getSystemSetting('entraid-yale-login-button-logo')) ?? $this->framework->getUrl('assets/images/YU.png', true, true),//'<i class="fas fa-sign-in-alt"></i>',
            'localLoginButtonBackgroundColor'      => $this->framework->getSystemSetting('local-login-button-background-color') ?? 'transparent',//'#00a9e0',
            'localLoginButtonBackgroundColorHover' => $this->framework->getSystemSetting('local-login-button-background-color-hover') ?? 'transparent',//'#32bae6',
            'localLoginButtonText'                 => $this->framework->getSystemSetting('local-login-button-text') ?? 'Yale New Haven Health',
            'localLoginButtonLogo'                 => $this->framework->getSystemSetting('local-login-button-logo') ?? $this->framework->getUrl('assets/images/YNHH.png', true, true),//'<i class="fas fa-sign-in-alt"></i>',
        ];
    }

    private function getEdocFileContents($edocId) {
        if (empty($edocId)) {
            return;
        }
        $file = \REDCap::getFile($edocId);
        $contents = $file[2];

        echo 'data:'.$file[0].';base64,'.base64_encode($contents);
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
            .btn-yale {
                background-color:
                    <?= $loginButtonSettings['yaleLoginButtonBackgroundColor'] ?>;
                background-image: url('<?= $loginButtonSettings['yaleLoginButtonLogo'] ?>');
                width: auto;
            }

            .btn-yale:hover,
            .btn-yale:focus,
            .btn-yale:active,
            .btn-yale.btn-active,
            .btn-yale:active:focus,
            .btn-yale:active:hover {
                color: #fff !important;
                background-color:
                    <?= $loginButtonSettings['yaleLoginButtonBackgroundColorHover'] ?> !important;
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
                                            onclick="showProgress(1);window.location.href='<?= $this->addQueryParameter($redirect, self::$AUTH_QUERY, self::$YALE_AUTH) ?>';">
                                            <img src="<?= $loginButtonSettings['yaleLoginButtonLogo'] //?? $this->framework->getUrl('assets/images/YU.png') ?>"
                                                class="login-logo" alt="Yale University">
                                        </li>
                                        <li class="list-group-item list-group-item-action login-option"
                                            onclick="showProgress(1);window.location.href='<?= $this->addQueryParameter($redirect, self::$AUTH_QUERY, self::$YNHH_AUTH) ?>';">
                                            <img src="<?= $this->framework->getUrl('assets/images/YNHH.png') ?>"
                                                class="login-logo">
                                        </li>
                                    </ul>
                                </div>
                                <a href="<?= $this->addQueryParameter($this->curPageURL(), self::$AUTH_QUERY, self::$LOCAL_AUTH) ?>"
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

    private function convertTableUserToYaleUser(string $userid)
    {
        if ( empty($userid) ) {
            return;
        }
        try {
            $SQL   = 'DELETE FROM redcap_auth WHERE username = ?';
            $query = $this->framework->query($SQL, [ $userid ]);
            $this->setYaleUser($userid);
            return;
        } catch ( \Exception $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error converting table user to YALE user', [ 'error' => $e->getMessage() ]);
            return;
        }
    }

    private function convertYaleUsertoTableUser(string $userid)
    {
        if ( empty($userid) ) {
            return;
        }
        try {
            $SQL   = "INSERT INTO redcap_auth (username) VALUES (?)";
            $query = $this->framework->query($SQL, [ $userid ]);
            \Authentication::resetPasswordSendEmail($userid);
            $this->setYaleUser($userid, false);
            return;
        } catch ( \Exception $e ) {
            $this->framework->log('Yale REDCap Authenticator: Error converting YALE user to table user', [ 'error' => $e->getMessage() ]);
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

    public function handleLogout()
    {
        $yale_entra_id = isset($_SESSION['yale_entraid_id']) ? $_SESSION['yale_entraid_id'] : null;
        $ynhh_entra_id = isset($_SESSION['ynhh_entraid_id']) ? $_SESSION['ynhh_entraid_id'] : null;
        session_unset();
        session_destroy();
        if (!is_null($yale_entra_id)) {
            $this->handleYaleLogout($yale_entra_id);
        }
        if (!is_null($ynhh_entra_id)) {
            $this->handleYnhhLogout($ynhh_entra_id);
        }
    }

    private function handleYaleLogout($entraid)
    {
        $authenticator = new Yale_EntraID_Authenticator($this);
        $authenticator->logout($entraid);
    }

    private function handleYnhhLogout($entraid)
    {
        $authenticator = new YNHH_SAML_Authenticator('http://localhost:33810', $this->framework->getUrl('YNHH_SAML_ACS.php', true));
        $authenticator->logout($entraid);
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
            $this->framework->log('Yale Authenticator: Error updating user details', [ 'error' => $e->getMessage() ]);
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
            $this->framework->log('Yale Authenticator: Error inserting user details', [ 'error' => $e->getMessage() ]);
        }
    }

    public function isYaleUser($username)
    {
        return !\Authentication::isTableUser($username) && $this->framework->getSystemSetting('yale-user-' . $username) === true;
    }

    public function getUserType($username)
    {
        if ( $this->isYaleUser($username) ) {
            return 'YALE';
        }
        if ( \Authentication::isTableUser($username) ) {
            return 'table';
        }
        if ( $this->inUserAllowlist($username) ) {
            return 'allowlist';
        }
        return 'unknown';
    }

    public function setYaleUser($userid, bool $value = true)
    {
        $this->framework->setSystemSetting('yale-user-' . $userid, $value);
    }

    private function addYaleInfoToBrowseUsersTable($page)
    {
        if ( !$page === 'ControlCenter/view_users.php' || !$this->framework->getSystemSetting('custom-login-page-enabled') == 1) {
            return;
        }

        $this->framework->initializeJavascriptModuleObject();

        parse_str($_SERVER['QUERY_STRING'], $query);
        if ( isset($query['username']) ) {
            $userid   = $query['username'];
            $userType = $this->getUserType($userid);
        }

        ?>
            <script>
                var authenticator = <?= $this->getJavascriptModuleObjectName() ?>;

                function convertTableUserToYaleUser() {
                    const username = $('#user_search').val();
                    Swal.fire({
                        title: "Are you sure you want to convert this table-based user to a YALE user?",
                        icon: "warning",
                        showCancelButton: true,
                        confirmButtonText: "Convert to YALE User"
                    }).then((result) => {
                        if (result.isConfirmed) {
                            authenticator.ajax('convertTableUserToYaleUser', {
                                username: username
                            }).then(() => {
                                location.reload();
                            });
                        }
                    });
                }

                function convertYaleUsertoTableUser() {
                    const username = $('#user_search').val();
                    Swal.fire({
                        title: "Are you sure you want to convert this YALE user to a table-based user?",
                        icon: "warning",
                        showCancelButton: true,
                        confirmButtonText: "Convert to Table User"
                    }).then((result) => {
                        if (result.isConfirmed) {
                            authenticator.ajax('convertYaleUsertoTableUser', {
                                username: username
                            }).then(() => {
                                location.reload();
                            });
                        }
                    });
                }

                function addTableRow(userType) {
                    let yaleUserText = '';
                    switch (userType) {
                        case 'YALE':
                            yaleUserText =
                                `<strong>${userType}</strong> <input type="button" style="font-size:11px" onclick="convertYaleUsertoTableUser()" value="Convert to Table User">`;
                            break;
                        case 'allowlist':
                            yaleUserText = `<strong>${userType}</strong>`;
                            break;
                        case 'table':
                            yaleUserText =
                                `<strong>${userType}</strong> <input type="button" style="font-size:11px" onclick="convertTableUserToYaleUser()" value="Convert to YALE User">`;
                            break;
                        default:
                            yaleUserText = `<strong>${userType}</strong>`;
                            break;
                    }
                    console.log($('#indv_user_info'));
                    $('#indv_user_info').append('<tr id="userTypeRow"><td class="data2">User type</td><td class="data2">' +
                        yaleUserText + '</td></tr>');
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

    public function checkYNHHAuth()
    {
        $isAuthed = false;
        try {
            if ( isset($_GET['authed']) ) {
                return;
            }

            // $protocol      = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
            // $curPageURL    = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            $curPageURL    = $this->curPageURL();
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

    private function isLoggedIntoREDCap()
    {
        return (defined('USERID') && USERID !== '') || $this->framework->isAuthenticated();
    }

    private function needsCustomLogin(string $page) {
        return  $this->framework->getSystemSetting('custom-login-page-enabled') == 1 &&
                !$this->resettingPassword($page) &&
                !$this->doingLocalLogin() &&
                $this->inLoginFunction() &&
                \ExternalModules\ExternalModules::getUsername() === null &&
                !\ExternalModules\ExternalModules::isNoAuth();
    }

    private function doingLocalLogin() {
        return isset($_GET[self::$AUTH_QUERY]) && $_GET[self::$AUTH_QUERY] == self::$LOCAL_AUTH;
    }

    private function doingYaleAuth() {
        return isset($_GET[self::$AUTH_QUERY]) && $_GET[self::$AUTH_QUERY] == self::$YALE_AUTH;
    }

    private function doingYNHHAuth() {
        return isset($_GET[self::$AUTH_QUERY]) && $_GET[self::$AUTH_QUERY] == self::$YNHH_AUTH;
    }

    private function resettingPassword(string $page) {
        return (isset($_GET['action']) && $_GET['action'] == 'passwordreset') || $page == 'Authentication/password_recovery.php';
    }

    private function addReplaceLogoutLinkScript() {
        $username = $this->framework->getUser()->getUsername();
        if (!$this->isYaleUser($username) || !$this->framework->getSystemSetting('custom-login-page-enabled') == 1) {
            return;
        }
        $logout_url = $this->framework->getUrl('logout.php');
        ?>
        <script>
            $(document).ready(function () {
                const link = document.querySelector('#nav-tab-logout a');
                if (link) {
                    link.href = '<?=$logout_url?>';
                }
            });
        </script>
        <?php
    }
}