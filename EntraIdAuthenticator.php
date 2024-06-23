<?php

namespace YaleREDCap\EntraIdAuthenticator;

/**
 * @property \ExternalModules\Framework $framework
 * @see Framework
 */

require_once 'classes/Attestation.php';
require_once 'classes/Authenticator.php';
require_once 'classes/ESignatureHandler.php';
require_once 'classes/EntraIdSettings.php';
require_once 'classes/Users.php';
require_once 'classes/Utilities.php';

class EntraIdAuthenticator extends \ExternalModules\AbstractExternalModule
{

    public static $AUTH_QUERY = 'authtype';
    public static $SITEID_QUERY = 'sid';
    public static $LOCAL_AUTH = 'local';
    public static $ENTRAID_SESSION_ID_COOKIE = 'entraid-session-id';
    public static $USER_TYPE_SETTING_PREFIX = 'entraid-user-';
    public static $USER_ATTESTATION_SETTING_PREFIX = 'entraid-attestation-';

    public function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
    {
        try {
            // No-auth
            if ( $action === 'handleAttestation' ) {
                $attestation = new Attestation($this, $payload['username'], $payload['siteId'], $payload['logId']);
                return $attestation->handleAttestationAjax();
            }

            // Admins only
            if ( !$this->framework->getUser()->isSuperUser() ) {
                throw new \Exception($this->framework->tt('error_1'));
            }
            if ( $action === 'getUserType' ) {
                $users = new Users($this);
                return $users->getUserType($payload['username']);
            }
            if ( $action === 'convertTableUserToEntraIdUser' ) {
                $users = new Users($this);
                return $users->convertTableUserToEntraIdUser($payload['username'], $payload['siteId']);
            }
            if ( $action === 'convertTableUsersToEntraIdUsers' ) {
                $usernames = $payload['usernames'];
                $siteId    = $payload['siteId'];
                $users     = new Users($this);
                if ( count($usernames) === 1 ) {
                    return $users->convertTableUserToEntraIdUser($usernames[0], $siteId);
                }
                return $users->convertTableUsersToEntraIdUsers($usernames, $siteId);
            }
            if ( $action == 'convertEntraIdUsertoTableUser' ) {
                $users = new Users($this);
                return $users->convertEntraIdUsertoTableUser($payload['username']);
            }
            if ( $action === 'convertEntraIdUsersToTableUsers' ) {
                $usernames = $payload['usernames'];
                $users     = new Users($this);
                if ( count($usernames) === 1 ) {
                    return $users->convertEntraIdUsertoTableUser($usernames[0]);
                }
                return $users->convertEntraIdUserstoTableUsers($usernames);
            }
            if ( $action === 'getEntraIdUsers' ) {
                $users = new Users($this);
                return $users->getAllUserData();
            }
        } catch ( \Throwable $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error in AJAX', [ 'error' => $e->getMessage() ]);
        }
    }

    public function redcap_every_page_before_render($project_id = null)
    {
        try {
            global $userid;

            // Check if we're in a page that needs to be handled
            $page = defined('PAGE') ? PAGE : null;
            if ( empty($page) ) {
                return;
            }

            // Don't do anything for SYSTEM user
            if ( defined('USERID') && USERID === 'SYSTEM' ) {
                return;
            }

            // If a user is being deleted, also delete their relevant module settings
            if ( $page === 'ControlCenter/delete_user.php' ) {
                try {
                    $username = trim($_POST['username']);
                    $Users    = new Users($this);
                    // This method performs authorization checks prior to deletion
                    $Users->deleteUser($username);
                } catch ( \Throwable $e ) {
                    $this->framework->log('Entra ID REDCap Authenticator: Error deleting user', [ 'user to delete' => $this->framework->escape($username), 'error' => $e->getMessage() ]);
                }
                return;
            }

            // Handle logout
            if ( isset($_GET['logout']) ) {
                \Authentication::checkLogout();
                return;
            }

            // Handle E-Signature form action
            if ( $page === 'Locking/single_form_action.php' && $_SERVER['REQUEST_METHOD'] === 'POST' ) {
                $users             = new Users($this);
                $site              = $users->getUserType();
                $authType          = $site['authType'];
                $esignatureHandler = new ESignatureHandler($this);
                $esignatureHandler->handleRequest($_POST, $authType);
                return;
            }

            // No need to do anything for posts otherwise (assuming we're not in the login function)
            if ( $_SERVER['REQUEST_METHOD'] === 'POST' && !Utilities::inLoginFunction() ) {
                return;
            }

            // Don't do anything if we're resetting a password
            if ( Utilities::resettingPassword($page) ) {
                return;
            }

            // Already logged in to REDCap
            if ( $this->isLoggedIntoREDCap() ) {
                $username = $this->getUserId();
                $users    = new Users($this);
                $userType = $users->getUserType($username);
                if ( Utilities::doingLocalLogin() || $userType['authValue'] === self::$LOCAL_AUTH ) {
                    // Local/LDAP user just logged in - Check if attestation is needed
                    $siteId = $this->inferSiteId($userType);
                    if ( isset($_GET[self::$SITEID_QUERY]) && $this->framework->getSystemSetting('convert-table-user-to-entraid-user') == 1 ) {
                        $users->setEntraIdUser($username, $siteId);
                    }
                    $attestation = new Attestation($this, $username, $siteId);
                    if ( $attestation->needsAttestationLocal() ) {
                        $attestation->showAttestationPage([ 'username' => $username ], Utilities::curPageURL());
                        $this->exitAfterHook();
                        return;
                    }

                    // Otherwise just redirect to the page without the auth query
                    if ( isset($_GET[self::$AUTH_QUERY]) ) {
                        $cleanUrl = Utilities::stripQueryParameter(Utilities::curPageURL(), self::$AUTH_QUERY);
                        $cleanUrl = Utilities::stripQueryParameter($cleanUrl, self::$SITEID_QUERY);
                        $this->redirectAfterHook($cleanUrl);
                    }
                }
                if ( !$users->checkAllowlist($username) ) {
                    $this->showNoUserAccessPage($username);
                    $this->framework->exitAfterHook();
                }
                return;
            }

            $username = $this->getUserId();
            if ( !$this->isLoggedIntoREDCap() && isset($username) && $username !== 'SYSTEM' && Utilities::inAuthenticateFunction() ) {
                // Check if user does not have an email address or email has not been verified
                if ( !$this->userHasVerifiedEmail($username) ) {
                    // This sets the $userid global, which is used in the email update page 
                    $userid = $username;
                    $this->showEmailUpdatePage();
                    $this->exitAfterHook();
                    return;
                }
            }

            // Only authenticate if we're asked to
            if ( isset($_GET[self::$AUTH_QUERY]) && !Utilities::doingLocalLogin() ) {
                $authType      = filter_input(INPUT_GET, self::$AUTH_QUERY, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                $authenticator = new Authenticator($this, "");
                $authenticator->handleEntraIdAuth($authType, Utilities::curPageURL());
            }

            // If not logged in, Auth Type is not set, but Site ID query is still defined, remove it from URL and redirect
            if ( empty($_GET[self::$AUTH_QUERY]) && isset($_GET[self::$SITEID_QUERY]) ) {
                $cleanUrl = Utilities::stripQueryParameter(Utilities::curPageURL(), self::$SITEID_QUERY);
                $this->redirectAfterHook($cleanUrl);
                return;
            }

            // Modify the login page
            if ( Utilities::needsModifiedLogin($page, $this) ) {
                $this->modifyLoginPage(Utilities::curPageURL());
                return;
            }

            // If doing local login, append a link to the custom login page
            if (
                Utilities::doingLocalLogin() && $this->framework->getSystemSetting('custom-login-page-type') !== 'none'
            ) {
                $this->addCustomLoginLinkScript();
                return;
            }

        } catch ( \Throwable $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error', [ 'error' => $e->getMessage() ]);
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
        $username = $this->getUserId();
        $users    = new Users($this);
        if (
            !$users->isEntraIdUser($username) ||
            $this->framework->getSystemSetting('custom-login-page-type') === 'none' ||
            $users->getUserType($username)['authType'] === self::$LOCAL_AUTH
        ) {
            return;
        }
        $esignatureHandler = new ESignatureHandler($this);
        $esignatureHandler->addEsignatureScript();
    }

    /**
     * This is a CRON method
     * Sends password reset emails in a queued fashion
     * @return void
     */
    public function sendPasswordResetEmails()
    {
        try {
            $neededMessage    = 'password-reset-needed';
            $completeMessage  = 'password-reset';
            $limitSeconds     = 60;
            $limitOccurrences = 150;

            $getUsersSql = 'SELECT username_to_reset WHERE message = ?';
            $getUsersQ   = $this->framework->queryLogs($getUsersSql, [ $neededMessage ]);
            $usernames   = [];
            while ( $row = $getUsersQ->fetch_assoc() ) {
                $usernames[] = $row['username_to_reset'];
            }
            if ( empty($usernames) ) {
                return;
            }

            $limitReached = $this->throttle("message = ?", [ $completeMessage ], $limitSeconds, $limitOccurrences);
            if ( !$limitReached ) {
                $users = new Users($this);
                foreach ( $usernames as $username ) {
                    $result = \Authentication::resetPasswordSendEmail($username);
                    $users->setEntraIdUser($username, false);
                    if ( $result ) {
                        $this->framework->log($completeMessage, [ 'username_to_reset' => $username ]);
                        $this->framework->removeLogs('message = ? AND username_to_reset = ? AND project_id IS NULL', [ $neededMessage, $username ]);
                    }
                }
            }
        } catch ( \Exception $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error sending password reset emails', [ 'error' => $e->getMessage() ]);
        }
    }

    private function addEntraIdInfoToBrowseUsersTable($page)
    {
        if ( $page !== 'ControlCenter/view_users.php' || $this->framework->getSystemSetting('custom-login-page-type') === 'none' ) {
            return;
        }

        $settings = new EntraIdSettings($this);
        $sites    = $settings->getAllSettings() ?? [];
        $siteData = [];
        foreach ( $sites as $site ) {
            $siteData[$site['siteId']] = $site['authValue'] . ' (' . $site['label'] . ')';
        }

        $this->framework->initializeJavascriptModuleObject();

        parse_str($_SERVER['QUERY_STRING'], $query);
        if ( isset($query['username']) ) {
            $username = $query['username'];
            $users    = new Users($this);
            $site     = $users->getUserType($username);
        }

        ?>
        <script>
            var authenticator = <?= $this->getJavascriptModuleObjectName() ?>;
            var sites = JSON.parse('<?= json_encode($siteData) ?>');

            function convertTableUserToEntraIdUser() {
                const username = $('#user_search').val();
                Swal.fire({
                    title: "<?= $this->framework->tt('convert_1') ?>",
                    input: 'select',
                    inputOptions: sites,
                    icon: "warning",
                    showCancelButton: true,
                    confirmButtonText: "<?= $this->framework->tt('convert_2') ?>"
                }).then((result) => {
                    console.log(result);
                    if (result.isConfirmed) {
                        let site = result.value;
                        console.log(site);
                        authenticator.ajax('convertTableUserToEntraIdUser', {
                            username: username,
                            siteId: site
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

            function addTableRow(siteJson) {
                const site = JSON.parse(siteJson);
                let userText = '';
                if (site['siteId'] === false) {
                    switch (site['authType']) {
                        case 'allowlist':
                            userText = `<strong><?= $this->framework->tt('user_types_1') ?></strong>`;
                            break;
                        case 'table':
                            userText =
                                `<strong><?= $this->framework->tt('user_types_2') ?></strong> <input type="button" style="font-size:11px" onclick="convertTableUserToEntraIdUser()" value="Convert to Entra ID User">`;
                            break;
                    }
                } else {
                    userText = `<strong>${site['label']}</strong> (${site['authType']}) <input type="button" style="font-size:11px" onclick="convertEntraIdUsertoTableUser()" value="<?= $this->framework->tt('convert_4') ?>">`;
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
                        }).then((site) => {
                            $('#view_user_div').html(data);
                            addTableRow(JSON.stringify(site));
                            enableUserSearch();
                            highlightTable('indv_user_info', 1000);
                        });
                    }
                );
            }

            <?php if ( isset($username) ) { ?>
                window.requestAnimationFrame(() => {
                    addTableRow('<?= json_encode($site) ?>')
                });
            <?php } ?>

            $(document).ready(function () {
                <?php if ( isset($username) ) { ?>
                    if (!$('#userTypeRow').length) {
                        view_user('<?= $username ?>');
                    }

                <?php } ?>
            });
        </script>
        <?php
    }

    private function isLoggedIntoREDCap()
    {
        if ( !(defined('USERID') && USERID !== '') || !$this->framework->isAuthenticated() ) { // || isset($_SESSION['username']);
            return false;
        }
        $username = $this->getUserId();
        $users    = new Users($this);
        if ( $users->userExists($username) ) {
            return true;
        }
        return false;
    }

    private function addReplaceLogoutLinkScript()
    {
        try {
            if ( !$this->isLoggedIntoREDCap() ) {
                return;
            }
            $username = $this->getUserId();
            $users    = new Users($this);
            if ( !$users->isEntraIdUser($username) || $this->framework->getSystemSetting('custom-login-page-type') === 'none' ) {
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

                    const projectLink = document.querySelector('#username-reference ~ span a');
                    if (projectLink) {
                        projectLink.href = '<?= $logout_url ?>';
                    }
                });
            </script>
            <?php
        } catch ( \Throwable $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error adding replace logout link script', [ 'error' => $e->getMessage() ]);
        }
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
        $contactLinkHref = trim($homepage_contact_url) == '' ? 'mailto:' . $homepage_contact_email : trim($homepage_contact_url);
        $contactLink     = '<a style=\"font-size:13px;text-decoration:underline;\" href=\"' . $contactLinkHref . '\">' . $homepage_contact . '</a>';
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
                                                        '<img src="' . Utilities::getEdocFileContents($site['loginButtonLogo']) . '" class="login-logo" alt="' . $site['label'] . '">' :
                                                        '<span class="login-label">' . $site['label'] . '</span>';
                                                    $redirect = Utilities::addQueryParameter($redirect, self::$AUTH_QUERY, $site['authValue']);
                                                    $redirect = Utilities::addQueryParameter($redirect, self::$SITEID_QUERY, $site['siteId']);
                                                    ?>
                                                        <li class="list-group-item list-group-item-action login-option"
                                                        onclick="showProgress(1);window.location.href='<?= $redirect ?>';">
                                                        <?= $loginImg ?>
                                                    </li>
                                                <?php } ?>
                                            </ul>
                                        </div>
                                        <hr>
                                        <a href="<?= Utilities::addQueryParameter(Utilities::curPageURL(), self::$AUTH_QUERY, self::$LOCAL_AUTH) ?>"
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
        $siteId = $this->inferSiteId([]);
        if ( !empty($siteId) && $siteId !== self::$LOCAL_AUTH ) {
            $customLogin = true;
            $settings    = new EntraIdSettings($this);
            $site        = $settings->getSettings($siteId);
            $logoImg     = $site['loginButtonLogo'] ?
                '<img src="' . Utilities::getEdocFileContents($site['loginButtonLogo']) . '" class="login-logo" alt="' . $site['label'] . '">' :
                '<span class="login-label">' . $site['label'] . '</span>';
        }
        ?>
        <style>
            .login-logo,
            .login-label {
                max-width: 350px;
                height: 53px;
                object-fit: contain;
                display: flex;
                justify-content: space-evenly;
                align-items: center;
                margin-bottom: 20px;
            }

            .login-label {
                font-weight: bold;
            }
        </style>
        <script>
            document.addEventListener("DOMContentLoaded", function () {
                const loginForm = document.querySelector('#rc-login-form form[name="form"]');
                if (loginForm) {

                    <?php if ( $customLogin ) { ?>
                        // Add Logo / label
                        const logoImg = $('<?= $logoImg ?>');
                        loginForm.parentElement.prepend(logoImg.get(0));

                        // Remove password reset link
                        loginForm.querySelector('a').remove();
                        document.getElementById('login_btn').parentElement.style.marginLeft = '140px';
                    <?php } ?>


                    const link = document.createElement('a');

                    const url = new URL(window.location);
                    const p = url.searchParams;
                    p.delete('<?= self::$AUTH_QUERY ?>');
                    p.delete('<?= self::$SITEID_QUERY ?>');

                    link.href = url.href;
                    link.innerText = '<?= $this->framework->tt('login_3') ?>';
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

    public function showNoUserAccessPage($username)
    {
        global $homepage_contact, $homepage_contact_email, $lang;
        session_unset();
        session_destroy();
        ?>
        <style>
            body {
                font: normal 13px "Open Sans", Helvetica, Arial, Helvetica, sans-serif;
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
                <?= $lang['config_functions_78'] ?>"<b><?= $username ?></b>"<?= $lang['period'] ?>
                <?= $lang['config_functions_79'] ?> <a
                    href='mailto:$homepage_contact_email'><?= $homepage_contact ?></a><?= $lang['period'] ?>
            </div>
            <button
                onclick="window.location.href='<?= APP_PATH_WEBROOT_FULL ?>index.php?logout=1'"><?= $this->framework->tt('error_5') ?></button>
            <div id="footer"><?= \REDCap::getCopyright() ?></div>
        </div>
        <?php
    }

    public function redcap_module_save_configuration($project_id)
    {
        if ( !empty($project_id) ) {
            return;
        }

        // Handle Site IDs
        $sites   = $this->getSystemSetting('entraid-site');
        $siteIds = $this->getSystemSetting('entraid-site-id');

        foreach ( $sites as $index => $site ) {
            if ( empty($siteIds) ) {
                $siteIds = [];
            }
            if ( empty($siteIds[$index]) ) {
                $siteIds[$index] = Utilities::generateSiteId();
            }
        }

        $this->setSystemSetting('entraid-site-id', $siteIds);

        // Handle Site Attestation Versioning
        // If the attestation version changes, log the new version
        Attestation::saveAttestationVersions($siteIds, $this);
    }

    public function redcap_module_link_check_display($project_id, $link)
    {
        if ( !is_null($project_id) ) {
            return null;
        }

        $loginType = $this->framework->getSystemSetting('custom-login-page-type');
        if ( $loginType === 'none' ) {
            return null;
        }

        return $link;

    }

    private function getSiteIdFromAuthValue($authValue = '') : string
    {
        try {
            $settings = new EntraIdSettings($this);
            $site     = $settings->getSettingsByAuthValue($authValue ?? '');
            return $site['siteId'] ?? '';
        } catch ( \Throwable $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error', [ 'error' => $e->getMessage() ]);
            return '';
        }
    }

    private function inferSiteId(array $userType = [])
    {
        $siteId = filter_input(INPUT_GET, self::$SITEID_QUERY, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        if ( $this->verifySiteId($siteId) ) {
            return $siteId;
        }
        $siteId = $this->getSiteIdFromAuthValue($_GET[self::$AUTH_QUERY]);
        if ( $this->verifySiteId($siteId) ) {
            return $siteId;
        }
        $siteId = $userType['siteId'];
        if ( $siteId ) {
            return $siteId;
        }
        return self::$LOCAL_AUTH;
    }

    private function verifySiteId($siteId)
    {
        if ( empty($siteId) ) {
            return false;
        }
        $settings = new EntraIdSettings($this);
        $site     = $settings->getSettings($siteId);
        return $site['siteId'] === $siteId;
    }

    public function getUserId()
    {
        try {
            if ( isset($_SESSION['username']) ) {
                return $_SESSION['username'];
            } elseif ( defined('USERID') && USERID !== '' ) {
                return USERID;
            } else {
                return $this->framework->getUser()->getUsername();
            }
        } catch ( \Throwable $e ) {
            return null;
        }
    }

    public function userHasVerifiedEmail($username)
    {
        $userInfo = \User::getUserInfo($username);
        return !(empty($userInfo) || $userInfo['user_email'] == "" || ($userInfo['user_email'] != "" && $userInfo['email_verify_code'] != ""));
    }

    public function showEmailUpdatePage()
    {
        global $lang, $userid;

        $ticketLink      = $this->getTicketLink();
        $lang['user_02'] .= '<br><br>' . $this->framework->tt('email_update_1', [ $ticketLink, 'Open Support Ticket' ]) . '<br><em>' . $this->framework->tt('email_update_2') . '</em>';

        include APP_PATH_DOCROOT . 'Profile/user_info.php';
    }

    private function getTicketLink()
    {
        return $this->framework->getSystemSetting('entraid-ticket-url');
    }

    public function validateSettings($settings)
    {
        if ( !$this->checkSites($settings) ) {
            return 'One or more sites you are trying to delete have users assigned to them. Please remove those users from a site before deleting it.';
        }
    }

    private function checkSites(array $settings)
    {
        $sites         = $this->framework->getSystemSetting('entraid-site-id') ?? [];
        $proposedSites = $settings['entraid-site-id'];
        $removed       = array_diff($sites, $proposedSites);

        if ( !empty($removed) ) {
            $Users = new Users($this);
            foreach ( $removed as $removedSiteId ) {
                $users = $Users->getUsers($removedSiteId);
                if ( !empty($users) ) {
                    return false;
                }
            }
        }
        return true;
    }
}