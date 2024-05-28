<?php

namespace YaleREDCap\EntraIdAuthenticator;

/**
 * @property \ExternalModules\Framework $framework
 * @see Framework
 */

require_once 'classes/Authenticator.php';
require_once 'classes/ESignatureHandler.php';
require_once 'classes/EntraIdSettings.php';

class EntraIdAuthenticator extends \ExternalModules\AbstractExternalModule
{

    static $AUTH_QUERY = 'authtype';
    static $LOCAL_AUTH = 'local';
    static $ENTRAID_URL_COOKIE = 'entraid-origin-url';
    static $ENTRAID_SESSION_ID_COOKIE = 'entraid-session-id';

    public function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
    {
        // Admins only
        if ( !$this->framework->getUser()->isSuperUser() ) {
            throw new \Exception($this->framework->tt('error_1'));
        }
        if ( $action === 'getUserType' ) {
            return $this->getUserType($payload['username']);
        }
        if ( $action === 'convertTableUserToEntraIdUser' ) {
            return $this->convertTableUserToEntraIdUser($payload['username'], $payload['authType']);
        }
        if ( $action == 'convertEntraIdUsertoTableUser' ) {
            return $this->convertEntraIdUsertoTableUser($payload['username']);
        }
    }

    public function redcap_every_page_before_render($project_id = null)
    {
        try {
            $page = defined('PAGE') ? PAGE : null;
            if ( empty($page) ) {
                return;
            }

            if ( isset($_GET['logout']) && $_GET['logout'] ) {
                \Authentication::checkLogout();
                return;
            }

            // Handle E-Signature form action
            if ( $page === 'Locking/single_form_action.php' && $_SERVER['REQUEST_METHOD'] === 'POST') {
                $authType          = $this->getUserType();
                $esignatureHandler = new ESignatureHandler($this);
                $esignatureHandler->handleRequest($_POST, $authType);
                return;
            }

            // Already logged in to REDCap
            if ( $this->isLoggedIntoREDCap() ) {
                if ( $this->doingLocalLogin() ) {
                    $cleanUrl = $this->stripQueryParameter($this->curPageURL(), self::$AUTH_QUERY);
                    $this->redirectAfterHook($cleanUrl);
                }
                $userid = $this->framework->getUser()->getUsername();
                if ( !$this->checkAllowlist($userid) ) {
                    $this->showNoUserAccessPage($userid);
                    $this->framework->exitAfterHook();
                }
                return;
            }

            // Only authenticate if we're asked to
            if ( isset($_GET[self::$AUTH_QUERY]) && !$this->doingLocalLogin() ) {
                $authType = filter_input(INPUT_GET, self::$AUTH_QUERY, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                $this->handleEntraIdAuth($authType, $this->curPageURL());
            }

            // Inject the custom login page 
            if ( $this->needsCustomLogin($page) ) {
                $this->showCustomLoginPage($this->curPageURL());
                $this->exitAfterHook();
                return;
            }

            // Or overwrite the login page
            if ( $this->needsModifiedLogin($page) ) {
                $this->modifyLoginPage($this->curPageURL());
                return;
            }

            // If doing local login, append a link to the custom login page
            if (
                $this->doingLocalLogin() && $this->framework->getSystemSetting('custom-login-page-type') !== 'none'
            ) {
                $this->addCustomLoginLinkScript();
                return;
            }

        } catch ( \Throwable $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error', [ 'error' => $e->getMessage() ]);
        }

    }

    public function handleEntraIDAuth($authType, $url)
    {
        try {
            $session_id = session_id();
            \Session::savecookie(self::$ENTRAID_SESSION_ID_COOKIE, $session_id, 0, true);
            \Session::savecookie(self::$ENTRAID_URL_COOKIE, $url, 0, true);
            $authenticator = new Authenticator($this, $authType, $session_id);
            $authenticator->authenticate();
            return true;
        } catch ( \Throwable $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error 1', [ 'error' => $e->getMessage() ]);
            session_unset();
            session_destroy();
            return false;
        }
    }

    public function loginEntraIDUser(array $userdata, string $authType)
    {
        global $enable_user_allowlist, $homepage_contact, $homepage_contact_email, $lang;
        try {
            $userid = $userdata['username'];
            if ( $userid === false || empty($userid) ) {
                return false;
            }

            // Check if user exists in REDCap, if not and if we are not supposed to create them, leave
            if ( !$this->userExists($userid) && !$this->framework->getSystemSetting('create-new-users-on-login') == 1 ) {
                exit($this->framework->tt('error_2'));
            }

            // Successful authentication
            $this->framework->log('Entra ID REDCap Authenticator: Auth Succeeded', [
                "EntraID Username" => $userid
            ]);

            // Trigger login
            \Authentication::autoLogin($userid);
            $_SESSION['entraid_id'] = $userdata['id'];

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
                ) {
                    $this->setUserDetails($userid, $userdata);
                }
                $this->setEntraIdUser($userid, $authType);
            }
            // If user is a table-based user, convert to Entra ID user
            elseif ( \Authentication::isTableUser($userid) && $this->framework->getSystemSetting('convert-table-user-to-entraid-user') == 1 ) {
                $this->convertTableUserToEntraIdUser($userid);
            }
            // otherwise just make sure they are logged as an Entra ID user
            elseif ( !\Authentication::isTableUser($userid) ) {
                $this->setEntraIdUser($userid, $authType);
            }

            // 2. If user allowlist is not enabled, all Entra ID users are allowed.
            // Otherwise, if not in allowlist, then give them an error page.
            if ( !$this->checkAllowlist($userid) ) {
                $this->showNoUserAccessPage($userid);
                return false;
            }
            return true;
        } catch ( \Throwable $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error 2', [ 'error' => $e->getMessage() ]);
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

        // Entra ID User information if applicable 
        $this->addEntraIdInfoToBrowseUsersTable($page);
    }

    public function redcap_data_entry_form()
    {
        $user = $this->framework->getUser();
        if ( !$this->isEntraIdUser($user->getUsername()) || $this->framework->getSystemSetting('custom-login-page-type') === 'none' ) {
            return;
        }
        $esignatureHandler = new ESignatureHandler($this);
        $esignatureHandler->addEsignatureScript();
    }

    private function getEdocFileContents($edocId)
    {
        if ( empty($edocId) ) {
            return;
        }
        $file     = \REDCap::getFile($edocId);
        $contents = $file[2];

        return 'data:' . $file[0] . ';base64,' . base64_encode($contents);
    }

    private function showCustomLoginPage(string $redirect)
    {
        $settings          = new EntraIdSettings($this);
        $entraIdSettings   = $settings->getAllSettings();
        $backgroundUrl     = $this->getEdocFileContents($this->framework->getSystemSetting('custom-login-page-background-image')) ?? $this->framework->getUrl('assets/images/New_Haven_1.jpg');
        $backgroundImgText = $this->framework->getSystemSetting('custom-login-page-background-image-copyright-text');
        $backgroundImgLink = empty($this->framework->getSystemSetting('custom-login-page-background-image-copyright-text')) ? '' : $this->framework->getSystemSetting('custom-login-page-background-image-copyright-link');
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
            #rc-login-form {
                display: none;
            }

            .login-option {
                cursor: pointer;
                border-radius: 0 !important;
                height: 70px;
            }

            .login-option:hover {
                background-color: #dddddd !important;
            }

            #login-card {
                border-radius: 0;
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

            .login-logo,
            .login-label {
                width: 100%;
                height: 100%;
                object-fit: contain;
                display: flex;
                justify-content: space-evenly;
                align-items: center;
            }

            .login-label {
                font-weight: bold;
            }

            div#working {
                top: 50% !important;
            }

            #my_page_footer a {
                text-decoration: none;
                color: inherit;
            }

            body {
                background-image: url('<?= $backgroundUrl ?>');
            }
        </style>

        <body>
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
                                        <?php foreach ( $entraIdSettings as $site ) {
                                            $loginImg = $site['loginButtonLogo'] ?
                                                '<img src="' . $this->getEdocFileContents($site['loginButtonLogo']) . '" class="login-logo" alt="' . $site['label'] . '">' :
                                                '<span class="login-label">' . $site['label'] . '</span>';
                                            ?>
                                            <li class="list-group-item list-group-item-action login-option"
                                                onclick="showProgress(1);window.location.href='<?= $this->addQueryParameter($redirect, self::$AUTH_QUERY, $site['authValue']) ?>';">
                                                <?= $loginImg ?>
                                            </li>
                                        <?php } ?>
                                    </ul>
                                </div>
                                <a href="<?= $this->addQueryParameter($this->curPageURL(), self::$AUTH_QUERY, self::$LOCAL_AUTH) ?>"
                                    class="text-primary">
                                    <?= $this->framework->tt('login_1') ?>
                                </a>
                                <div id="my_page_footer" class="text-secondary mt-4">
                                    <?= \REDCap::getCopyright() ?>
                                    <br>
                                    <span><a href="<?= $backgroundImgLink ?>" tabindex="-1" target="_blank"
                                            rel="noopener noreferrer"><?= $backgroundImgText ?></a>
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

    private function convertTableUserToEntraIdUser(string $userid, string $authType)
    {
        if ( empty($userid) ) {
            return;
        }
        try {
            $SQL   = 'DELETE FROM redcap_auth WHERE username = ?';
            $query = $this->framework->query($SQL, [ $userid ]);
            $this->setEntraIdUser($userid, $authType);
            return;
        } catch ( \Exception $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error converting table user to YALE user', [ 'error' => $e->getMessage() ]);
            return;
        }
    }

    private function convertEntraIdUsertoTableUser(string $userid)
    {
        if ( empty($userid) ) {
            return;
        }
        try {
            $SQL   = "INSERT INTO redcap_auth (username) VALUES (?)";
            $query = $this->framework->query($SQL, [ $userid ]);
            \Authentication::resetPasswordSendEmail($userid);
            $this->setEntraIdUser($userid, false);
            return;
        } catch ( \Exception $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error converting YALE user to table user', [ 'error' => $e->getMessage() ]);
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
        $authType = $this->getUserType();
        session_unset();
        session_destroy();
        $authenticator = new Authenticator($this, $authType);
        $authenticator->logout();
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

    public function isEntraIdUser($username)
    {
        return !\Authentication::isTableUser($username) && $this->framework->getSystemSetting('yale-user-' . $username) === true;
    }

    public function getUserType($username = null)
    {
        if ( $username === null ) {
            $username = $this->framework->getUser()->getUsername();
        }
        $entraidAuthType = $this->framework->getSystemSetting('entraid-user-' . $username);
        if ( $entraidAuthType ) {
            return $entraidAuthType;
        }
        if ( \Authentication::isTableUser($username) ) {
            return 'table';
        }
        if ( $this->inUserAllowlist($username) ) {
            return 'allowlist';
        }
        return 'unknown';
    }

    public function setEntraIdUser($userid, $value)
    {
        $this->framework->setSystemSetting('entraid-user-' . $userid, $value);
    }

    private function addEntraIdInfoToBrowseUsersTable($page)
    {
        if ( !$page === 'ControlCenter/view_users.php' || $this->framework->getSystemSetting('custom-login-page-type') === 'none' ) {
            return;
        }

        $settings  = new EntraIdSettings($this);
        $authTypes = $settings->getAuthValues() ?? [];

        $this->framework->initializeJavascriptModuleObject();

        parse_str($_SERVER['QUERY_STRING'], $query);
        if ( isset($query['username']) ) {
            $userid   = $query['username'];
            $userType = $this->getUserType($userid);
        }

        ?>
            <script>
                var authenticator = <?= $this->getJavascriptModuleObjectName() ?>;
                var authTypes = JSON.parse('<?= json_encode($authTypes) ?>');

                function convertTableUserToEntraIdUser() {
                    const username = $('#user_search').val();
                    Swal.fire({
                        title: "<?= $this->framework->tt('convert_1') ?>",
                        input: 'select',
                        inputOptions: authTypes,
                        icon: "warning",
                        showCancelButton: true,
                        confirmButtonText: "<?= $this->framework->tt('convert_2') ?>"
                    }).then((result) => {
                        if (result.isConfirmed) {
                            let userType = authTypes[result.value];
                            authenticator.ajax('convertTableUserToEntraIdUser', {
                                username: username,
                                authType: userType
                            }).then(() => {
                                location.reload();
                            });
                        }
                    });
                }

                function convertEntraIdUsertoTableUser() {
                    const username = $('#user_search').val();
                    Swal.fire({
                        title: "<?= $this->framework->tt('convert_3') ?>",
                        icon: "warning",
                        showCancelButton: true,
                        confirmButtonText: "<?= $this->framework->tt('convert_4') ?>"
                    }).then((result) => {
                        if (result.isConfirmed) {
                            authenticator.ajax('convertEntraIdUsertoTableUser', {
                                username: username
                            }).then(() => {
                                location.reload();
                            });
                        }
                    });
                }

                function addTableRow(userType) {
                    let userText = '';
                    switch (userType) {
                        case 'allowlist':
                            userText = `<strong><?= $this->framework->tt('user_types_1') ?></strong>`;
                            break;
                        case 'table':
                            userText =
                                `<strong><?= $this->framework->tt('user_types_2') ?></strong> <input type="button" style="font-size:11px" onclick="convertTableUserToEntraIdUser()" value="Convert to Entra ID User">`;
                            break;
                        default:
                            userText =
                                `<strong>${userType}</strong> <input type="button" style="font-size:11px" onclick="convertEntraIdUsertoTableUser()" value="<?= $this->framework->tt('convert_4') ?>">`;
                            break;
                    }
                    $('#indv_user_info').append('<tr id="userTypeRow"><td class="data2">User type</td><td class="data2">' +
                        userText + '</td></tr>');
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

    private function setUserCreationTimestamp($userid)
    {
        try {
            $SQL = "UPDATE redcap_user_information SET user_creation = ? WHERE username = ?";
            $this->framework->query($SQL, [ NOW, $userid ]);
        } catch ( \Exception $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error setting user creation timestamp', [ 'error' => $e->getMessage() ]);
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

    private function needsCustomLogin(string $page)
    {
        return $this->framework->getSystemSetting('custom-login-page-type') === "complete" &&
            !$this->resettingPassword($page) &&
            !$this->doingLocalLogin() &&
            $this->inLoginFunction() &&
            \ExternalModules\ExternalModules::getUsername() === null &&
            !\ExternalModules\ExternalModules::isNoAuth();
    }

    private function needsModifiedLogin(string $page)
    {
        return $this->framework->getSystemSetting('custom-login-page-type') === "modified" &&
            !$this->resettingPassword($page) &&
            !$this->doingLocalLogin() &&
            $this->inLoginFunction() &&
            \ExternalModules\ExternalModules::getUsername() === null &&
            !\ExternalModules\ExternalModules::isNoAuth();
    }

    private function doingLocalLogin()
    {
        return isset($_GET[self::$AUTH_QUERY]) && $_GET[self::$AUTH_QUERY] == self::$LOCAL_AUTH;
    }

    private function resettingPassword(string $page)
    {
        return (isset($_GET['action']) && $_GET['action'] == 'passwordreset') || $page == 'Authentication/password_recovery.php';
    }

    private function addReplaceLogoutLinkScript()
    {
        $username = $this->framework->getUser()->getUsername();
        if ( !$this->isEntraIdUser($username) || $this->framework->getSystemSetting('custom-login-page-type') === 'none' ) {
            return;
        }
        $logout_url = $this->framework->getUrl('logout.php');
        ?>
            <script>
                $(document).ready(function () {
                    const link = document.querySelector('#nav-tab-logout a');
                    if (link) {
                        link.href = '<?= $logout_url ?>';
                    }
                });
            </script>
            <?php
    }

    private function modifyLoginPage(string $redirect)
    {
        $settings        = new EntraIdSettings($this);
        $entraIdSettings = $settings->getAllSettings();
        ?>
            <style>
                #rc-login-form {
                    display: none;
                }

                .login-option {
                    cursor: pointer;
                    border-radius: 0 !important;
                    height: 70px;
                }

                .login-option:hover {
                    background-color: #dddddd !important;
                }

                #login-card {
                    border-radius: 0;
                    width: 502px;
                    height: auto;
                    margin: 0 auto;
                    left: 50%;
                    margin-left: -250px;
                    border: none;
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

                .login-logo,
                .login-label {
                    width: 100%;
                    height: 100%;
                    object-fit: contain;
                    display: flex;
                    justify-content: space-evenly;
                    align-items: center;
                }

                .login-label {
                    font-weight: bold;
                }

                div#working {
                    top: 50% !important;
                }

                #my_page_footer a {
                    text-decoration: none;
                    color: inherit;
                }
            </style>
            <?php

            global $login_logo, $institution, $login_custom_text, $homepage_announcement, $homepage_announcement_login, $homepage_contact, $homepage_contact_email, $homepage_contact_url;
            $contactLinkHref = trim($homepage_contact_url) == '' ? 'mailto:'.$homepage_contact_email : trim($homepage_contact_url);
            $contactLink = '<a style=\"font-size:13px;text-decoration:underline;\" href=\"'.$contactLinkHref.'\">'.$homepage_contact.'</a>';
            ?>
            <script>
                document.addEventListener("DOMContentLoaded", function () {
                    $(`<p style='font-size:13px;'><?= $this->framework->tt('contact_1') . $contactLink ?></p>
                            <div class="container text-center">
                                <div class="row align-items-center">
                                    <div class="col">
                                        <div class="card" id="login-card">
                                            <div class="card-body rounded-0">
                                                <div class="card align-self-center text-center mb-2 login-options rounded-0">
                                                    <ul class="list-group list-group-flush">
                                                        <?php foreach ( $entraIdSettings as $site ) {
                                                            $loginImg = $site['loginButtonLogo'] ?
                                                                '<img src="' . $this->getEdocFileContents($site['loginButtonLogo']) . '" class="login-logo" alt="' . $site['label'] . '">' :
                                                                '<span class="login-label">' . $site['label'] . '</span>';
                                                            ?>
                                                                    <li class="list-group-item list-group-item-action login-option"
                                                                    onclick="showProgress(1);window.location.href='<?= $this->addQueryParameter($redirect, self::$AUTH_QUERY, $site['authValue']) ?>';">
                                                                    <?= $loginImg ?>
                                                                </li>
                                                        <?php } ?>
                                                    </ul>
                                                </div>
                                                <hr>
                                                <a href="<?= $this->addQueryParameter($this->curPageURL(), self::$AUTH_QUERY, self::$LOCAL_AUTH) ?>"
                                                    class="text-primary">
                                                    <?= $this->framework->tt('login_1') ?>
                                                </a>
                                            </div>
                                </div>
                            </div>
                        </div>
                            </div>`).insertBefore('#rc-login-form');
                    });
            </script>
            <?php
    }

    private function addCustomLoginLinkScript()
    {
        ?>
            <script>
                document.addEventListener("DOMContentLoaded", function () {
                    const loginForm = document.querySelector('#rc-login-form form[name="form"]');
                    if (loginForm) {
                        const link = document.createElement('a');
                        link.href = '<?= $this->stripQueryParameter($this->curPageURL(), 'authtype') ?>';
                        link.innerText = '<?= $this->framework->tt('login_2') ?>';
                        link.classList.add('text-primary', 'text-center');
                        link.style.display = 'block';
                        link.style.marginTop = '10px';
                        link.style.width = 'fit-content';
                        loginForm.appendChild(document.createElement('hr'));
                        loginForm.appendChild(link);
                    }
                });
            </script>
            <?php
    }

    private function showNoUserAccessPage($userid) {
        global $homepage_contact, $homepage_contact_email, $lang;
        session_unset();
        session_destroy();
        ?>
        <style>
            body {
                font: normal 13px "Open Sans",Helvetica,Arial, Helvetica, sans-serif;
            }
            .container {
                width: 100%;
                height: 100%;
                display: flex;
                flex-direction: column;
                align-items: center;
            }
            .red {
                padding: 6px;
                border: 1px solid red;
                color: #800000;
                max-width: 1100px;
                background-color: #FFE1E1;
            }
            #footer {
                color: #888;
                font-size: 11px;
                text-align: center;
                margin: 0;
                padding: 15px 0 5px;
            }
        </style>
        <div class='container'>
            <div class='red' style='margin:40px 0 20px;padding:20px;'>
                <?= $lang['config_functions_78'] ?>"<b><?=$userid?></b>"<?= $lang['period'] ?>
                <?= $lang['config_functions_79'] ?> <a href='mailto:$homepage_contact_email'><?= $homepage_contact ?></a><?= $lang['period'] ?>
            </div>
            <button onclick="window.location.href='<?= APP_PATH_WEBROOT_FULL ?>index.php?logout=1'"><?= $this->framework->tt('error_5') ?></button>
            <div id="footer"><?= \REDCap::getCopyright() ?></div>
        </div>
        <?php
    }

    private function checkAllowlist($userid) {
        global $enable_user_allowlist;
        return !$enable_user_allowlist || \Authentication::isTableUser($userid) || $this->inUserAllowlist($userid) || $userid === 'SYSTEM';
    }
}