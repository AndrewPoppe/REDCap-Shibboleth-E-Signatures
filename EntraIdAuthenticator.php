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

    const AUTH_QUERY = 'authtype';
    const SITEID_QUERY = 'sid';
    const LOCAL_AUTH = 'local';
    const ENTRAID_SESSION_ID_COOKIE = 'entraid-session-id';
    const USER_TYPE_SETTING_PREFIX = 'entraid-user-';
    const USER_ATTESTATION_SETTING_PREFIX = 'entraid-attestation-';

    public function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
    {
        try {
            // No-auth
            if ( $action === 'handleAttestation' ) {
                $this->entraIdLog('Ajax: handleAttestation', [ 'payload' => json_encode($payload, JSON_PRETTY_PRINT) ], 'debug');
                $attestation = new Attestation($this, $payload['username'], $payload['siteId'], $payload['logId']);
                return $attestation->handleAttestationAjax();
            }

            // Admins only
            if ( !$this->framework->getUser()->isSuperUser() ) {
                throw new \Exception($this->framework->tt('error_1'));
            }
            if ( $action === 'getUserType' ) {
                $this->entraIdLog('Ajax: getUserType', [ 'payload' => json_encode($payload, JSON_PRETTY_PRINT) ], 'debug');
                $users = new Users($this);
                return $users->getUserType($payload['username']);
            }
            if ( $action === 'convertTableUserToEntraIdUser' ) {
                $this->entraIdLog('Ajax: convertTableUserToEntraIdUser', [ 'payload' => json_encode($payload, JSON_PRETTY_PRINT) ], 'debug');
                $users = new Users($this);
                return $users->convertTableUserToEntraIdUser($payload['username'], $payload['siteId']);
            }
            if ( $action === 'convertTableUsersToEntraIdUsers' ) {
                $this->entraIdLog('Ajax: convertTableUsersToEntraIdUsers', [ 'payload' => json_encode($payload, JSON_PRETTY_PRINT) ], 'debug');
                $usernames = $payload['usernames'];
                $siteId    = $payload['siteId'];
                $users     = new Users($this);
                if ( count($usernames) === 1 ) {
                    return $users->convertTableUserToEntraIdUser($usernames[0], $siteId);
                }
                return $users->convertTableUsersToEntraIdUsers($usernames, $siteId);
            }
            if ( $action === 'convertEntraIdUsertoTableUser' ) {
                $this->entraIdLog('Ajax: convertEntraIdUsertoTableUser', [ 'payload' => json_encode($payload, JSON_PRETTY_PRINT) ], 'debug');
                $users = new Users($this);
                return $users->convertEntraIdUsertoTableUser($payload['username']);
            }
            if ( $action === 'convertEntraIdUsersToTableUsers' ) {
                $this->entraIdLog('Ajax: convertEntraIdUsersToTableUsers', [ 'payload' => json_encode($payload, JSON_PRETTY_PRINT) ], 'debug');
                $usernames = $payload['usernames'];
                $users     = new Users($this);
                if ( count($usernames) === 1 ) {
                    return $users->convertEntraIdUsertoTableUser($usernames[0]);
                }
                return $users->convertEntraIdUserstoTableUsers($usernames);
            }
            if ( $action === 'getEntraIdUsers' ) {
                $this->entraIdLog('Ajax: getEntraIdUsers', [ 'payload' => json_encode($payload, JSON_PRETTY_PRINT) ], 'debug');
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
                    $this->entraIdLog('Deleting User', [ 'thisUsername' => $username ], 'debug');
                    $users = new Users($this);
                    // This method performs authorization checks prior to deletion
                    $users->deleteUser($username);
                } catch ( \Throwable $e ) {
                    $this->framework->log('Entra ID REDCap Authenticator: Error deleting user', [ 'user to delete' => $this->framework->escape($username), 'error' => $e->getMessage() ]);
                }
                return;
            }

            // Handle logout
            if ( isset($_GET['logout']) ) {
                $this->entraIdLog('Logging out', [], 'debug');
                \Authentication::checkLogout();
                return;
            }

            // Handle E-Signature form action
            if ( $page === 'Locking/single_form_action.php' && $_SERVER['REQUEST_METHOD'] === 'POST' ) {
                $this->entraIdLog('Handling E-Signature', [], 'debug');
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
                $this->entraIdLog('Resetting Password', [], 'debug');
                return;
            }

            // Already logged in to REDCap
            $username = $this->getUserId();
            if ( $this->isLoggedIntoREDCap() && $username !== 'SYSTEM' ) {
                $users    = new Users($this);
                $userType = $users->getUserType($username);
                $siteId   = $this->inferSiteId($userType);

                // Set user to Entra ID if they should be
                if (
                    isset($_GET[self::SITEID_QUERY]) &&
                    !$users->isEntraIdUser($username) &&
                    $this->framework->getSystemSetting('convert-table-user-to-entraid-user') == 1
                ) {
                    $this->entraIdLog('Setting user as Entra ID User', [ 'thisUsername' => $username, 'siteId' => $siteId ], 'debug');
                    $users->setEntraIdUser($username, $siteId);
                }

                // Show user attestation if needed
                $attestation = new Attestation($this, $username, $siteId);
                if ( $attestation->needsAttestation() ) {
                    $this->entraIdLog('Showing Attestation', [ 'thisUsername' => $username ], 'debug');
                    $attestation->showAttestationPage([ 'username' => $username ], Utilities::curPageURL());
                    $this->exitAfterHook();
                    return;
                }

                // Check allowlist if needed
                if ( !$users->checkAllowlist($username) ) {
                    $this->entraIdLog('Not in allow list', [], 'debug');
                    $this->showNoUserAccessPage($username);
                    $this->framework->exitAfterHook();
                }

                // Otherwise just redirect to the page without the auth query
                if ( isset($_GET[self::AUTH_QUERY]) ) {
                    $cleanUrl = Utilities::stripQueryParameter(Utilities::curPageURL(), self::AUTH_QUERY);
                    $cleanUrl = Utilities::stripQueryParameter($cleanUrl, self::SITEID_QUERY);
                    $this->redirectAfterHook($cleanUrl);
                }
                return;
            }

            // Not logged in to REDCap but does have a username
            // Means they are partway through logging in
            // Check if user does not have an email address or email has not been verified
            if (
                isset($username) &&
                $username !== 'SYSTEM' &&
                Utilities::inAuthenticateFunction() &&
                !$this->userHasVerifiedEmail($username)
            ) {
                // This sets the $userid global, which is used in the email update page
                $this->entraIdLog('Needs Email Verification Page', [], 'debug');
                $userid = $username;
                $this->showEmailUpdatePage();
                $this->exitAfterHook();
                return;
            }

            // Only authenticate if we're asked to
            if ( isset($_GET[self::AUTH_QUERY]) && !Utilities::doingLocalLogin() ) {
                $this->entraIdLog('Trying to Authenticate', [], 'debug');
                $authType      = filter_input(INPUT_GET, self::AUTH_QUERY, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                $authenticator = new Authenticator($this, "");
                $authenticator->handleEntraIdAuth($authType, Utilities::curPageURL());
            }

            // If not logged in, Auth Type is not set, but Site ID query is still defined, remove it from URL and redirect
            if ( empty($_GET[self::AUTH_QUERY]) && isset($_GET[self::SITEID_QUERY]) ) {
                $this->entraIdLog('Cleaning URL and Redirecting', [], 'debug');
                $cleanUrl = Utilities::stripQueryParameter(Utilities::curPageURL(), self::SITEID_QUERY);
                $this->redirectAfterHook($cleanUrl);
                return;
            }

            // Modify the login page
            if ( Utilities::needsModifiedLogin($page, $this) ) {
                $this->entraIdLog('Showing Login Page', [], 'debug');
                $this->modifyLoginPage(Utilities::curPageURL());
                return;
            }

            // If doing local login, append a link to the custom login page
            if (
                Utilities::doingLocalLogin() && $this->framework->getSystemSetting('custom-login-page-type') !== 'none'
            ) {
                $this->entraIdLog('Adding Login Link Script', [], 'debug');
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
            $users->getUserType($username)['authType'] === self::LOCAL_AUTH
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

        parse_str($_SERVER['QUERY_STRING'], $query);
        if ( isset($query['username']) ) {
            $username = $query['username'];
            $users    = new Users($this);
            $site     = $users->getUserType($username);
        }

        $this->framework->initializeJavascriptModuleObject();
        $this->framework->tt_transferToJavascriptModuleObject();
        $js = file_get_contents($this->framework->getSafePath('js/browseUsersTable.js'));
        $js = str_replace('__MODULE__', $this->framework->getJavascriptModuleObjectName(), $js);
        $js = str_replace('{{USERNAME}}', $username ?? "", $js);
        $js = str_replace('{{SITEDATA}}', json_encode($siteData), $js);
        $js = str_replace('{{SITEJSON}}', json_encode($site ?? []), $js);
        echo '<script type="text/javascript">' . $js . '</script>';
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
            // Only makes sense for logged-in users
            if ( !$this->isLoggedIntoREDCap() ) {
                return;
            }

            // Only replace if the user is an Entra ID user and the system settings are appropriate
            $username              = $this->getUserId();
            $users                 = new Users($this);
            $isEntraIdUser         = $users->isEntraIdUser($username);
            $showModifiedLoginPage = $this->framework->getSystemSetting('custom-login-page-type') !== 'none';
            if ( !$isEntraIdUser || !$showModifiedLoginPage ) {
                return;
            }

            $logout_url = $this->framework->getUrl('logout.php');
            $js         = file_get_contents($this->framework->getSafePath('js/logout.js'));
            $js         = str_replace('{{logout_url}}', $logout_url, $js);
            echo '<script type="text/javascript">' . $js . '</script>';
        } catch ( \Throwable $e ) {
            $this->framework->log('Entra ID REDCap Authenticator: Error adding replace logout link script', [ 'error' => $e->getMessage() ]);
        }
    }

    private function modifyLoginPage(string $redirect)
    {
        $settings        = new EntraIdSettings($this);
        $entraIdSettings = $settings->getAllSettings();
        $css             = file_get_contents($this->framework->getSafePath('css/loginPage.css'));
        echo '<style>' . $css . '</style>';

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
                                                            $loginImg     = $site['loginButtonLogo'] ?
                                                                '<img src="' . Utilities::getEdocFileContents($site['loginButtonLogo']) . '" class="login-logo" alt="' . $site['label'] . '">' :
                                                                '<span class="login-label">' . $site['label'] . '</span>';
                                                            $redirect_new = Utilities::addQueryParameter($redirect, self::AUTH_QUERY, $site['authValue']);
                                                            $redirect_new = Utilities::addQueryParameter($redirect_new, self::SITEID_QUERY, $site['siteId']);
                                                            ?>
                                                                    <li class="list-group-item list-group-item-action login-option"
                                                                    onclick="showProgress(1);window.location.href='<?= $redirect_new ?>';">
                                                                    <?= $loginImg ?>
                                                                </li>
                                                        <?php } ?>
                                                    </ul>
                                                </div>
                                                <hr>
                                                <a href="<?= Utilities::addQueryParameter(Utilities::curPageURL(), self::AUTH_QUERY, self::LOCAL_AUTH) ?>"
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
        if ( !empty($siteId) && $siteId !== self::LOCAL_AUTH ) {
            $customLogin = true;
            $settings    = new EntraIdSettings($this);
            $site        = $settings->getSettings($siteId);
            $logoImg     = $site['loginButtonLogo'] ?
                '<img src="' . Utilities::getEdocFileContents($site['loginButtonLogo']) . '" class="login-logo" alt="' . $site['label'] . '">' :
                '<span class="login-label">' . $site['label'] . '</span>';
        }
        $css = file_get_contents($this->framework->getSafePath('css/customLoginLink.css'));
        echo '<style>' . $css . '</style>';
        ?>
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
                    p.delete('<?= self::AUTH_QUERY ?>');
                    p.delete('<?= self::SITEID_QUERY ?>');

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
        $css = file_get_contents($this->framework->getSafePath('css/noUserAccess.css'));
        echo '<style>' . $css . '</style>';
        ?>
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
        $siteId = $userType['siteId'];
        if ( $this->verifySiteId($siteId) ) {
            return $siteId;
        }
        $siteId = filter_input(INPUT_GET, self::SITEID_QUERY, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        if ( $this->verifySiteId($siteId) ) {
            return $siteId;
        }
        $siteId = $this->getSiteIdFromAuthValue($_GET[self::AUTH_QUERY]);
        if ( $this->verifySiteId($siteId) ) {
            return $siteId;
        }
    
        return self::LOCAL_AUTH;
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
        try {
            $this->entraIdLog('Showing Email Verification Page', [ 'thisUsername' => $userid ], 'debug');
            $ticketLink      = $this->getTicketLink();
            $lang['user_02'] .= '<br><br>' . $this->framework->tt('email_update_1', [ $ticketLink, 'Open Support Ticket' ]) . '<br><em>' . $this->framework->tt('email_update_2') . '</em>';
            include APP_PATH_DOCROOT . 'Profile/user_info.php';
        } catch ( \Throwable $e ) {
            $this->entraIdLog('Entra Id Authenticator: Error Showing Email Update Page', [ 'error' => $e->getMessage() ], 'error');
        }
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
            $users = new Users($this);
            foreach ( $removed as $removedSiteId ) {
                $usernames = $users->getUsers($removedSiteId);
                if ( !empty($usernames) ) {
                    return false;
                }
            }
        }
        return true;
    }

    public function entraIdLog($message, $parameters, $level)
    {
        $debug = $this->getSystemSetting('entraid-debug');
        if ( $level !== 'debug' || $debug == 1 ) {
            $this->framework->log($message, $parameters);
        }
    }
}