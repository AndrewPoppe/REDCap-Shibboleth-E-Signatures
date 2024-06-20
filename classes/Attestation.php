<?php
namespace YaleREDCap\EntraIdAuthenticator;

class Attestation
{
    private EntraIdAuthenticator $module;
    private EntraIdSettings $settings;
    private string $username;
    private string $siteId;
    private $logId;

    public function __construct(EntraIdAuthenticator $module, string $username, string $siteId, $logId = null)
    {
        $this->module   = $module;
        $this->settings = new EntraIdSettings($module);
        $this->username = $module->framework->escape($username);
        $this->siteId   = $module->framework->escape($siteId);
        if ( !empty($logId) ) {
            $this->logId = $module->framework->escape($logId);
        }
    }

    public function handleAttestationAjax()
    {
        if ( $this->checkAttestationRequest() === true ) {
            return $this->handleAttestation();
        } else {
            return false;
        }
    }

    private function checkAttestationRequest()
    {
        $log = $this->module->framework->queryLogs('SELECT userid, siteId WHERE log_id = ?', [ $this->logId ]);
        while ( $row = $log->fetch_assoc() ) {
            if ( $row['userid'] === $this->username && $row['siteId'] === $this->siteId ) {
                return true;
            }
        }
        return false;
    }

    private function handleAttestation()
    {
        try {
            if ( empty($this->username) ) {
                return false;
            }
            $site = $this->settings->getSettings($this->siteId);
            if ( empty($site) ) {
                return false;
            }
            $version     = $site['attestationVersion'];
            $date = defined('NOW') ? NOW : date('Y-m-d H:i:s');
            $attestationText         = $site['attestationText'];
            $attestationCheckboxText = $site['attestationCheckboxText'];
            $logId = $this->module->framework->log('Entra ID REDCap Authenticator: Attestation', [
                'userid'                  => $this->username,
                'siteId'                  => $this->siteId,
                'version'                 => $version,
                'date'                    => $date,
                'attestationText'         => $attestationText,
                'attestationCheckboxText' => $attestationCheckboxText
            ]);
            $attestation = [
                'siteId'  => $this->siteId,
                'version' => $version,
                'date'    => $date,
                'logId'   => $logId,
                'attestationText' => $attestationText,
                'attestationCheckboxText' => $attestationCheckboxText
            ];
            $this->module->framework->setSystemSetting($this->module::$USER_ATTESTATION_SETTING_PREFIX . $this->username, json_encode($attestation));
            return true;
        } catch ( \Throwable $e ) {
            $this->module->framework->log('Entra ID REDCap Authenticator: Error handling attestation', [ 'error' => $e->getMessage() ]);
            return false;
        }
    }

    public function needsAttestation()
    {
        if ( $this->getLoginPageType() === 'none' ) {
            return false;
        }

        $userExists             = $this->module->userExists($this->username);
        $showAttestationSetting = $this->getAttestationSetting();
        $createUsers            = $this->createUsersOnLogin();
        $userAttested           = $this->isUserAttestationCurrent();

        // User is going to be created
        if (
            !$userExists &&
            $showAttestationSetting > 0 &&
            $createUsers &&
            !$userAttested
        ) {
            return true;
        }

        // User is just logging in
        if (
            $userExists &&
            $showAttestationSetting == 2 &&
            !$userAttested
        ) {
            return true;
        }

        return false;
    }

    private function getAttestationSetting()
    {
        $site = $this->settings->getSettings($this->siteId);
        return $site['showAttestation'];
    }

    private function getLoginPageType()
    {
        return $this->module->framework->getSystemSetting('custom-login-page-type');
    }

    private function createUsersOnLogin()
    {
        return $this->module->framework->getSystemSetting('create-new-users-on-login') == 1;
    }

    private function isLocalLogin()
    {
        return $_GET[EntraIdAuthenticator::$AUTH_QUERY] === EntraIdAuthenticator::$LOCAL_AUTH;
    }

    private function userWasJustCreated()
    {
        $userInfo = \User::getUserInfo($this->username);
        return empty($userInfo) || $userInfo['user_email'] == "" || ($userInfo['user_email'] != "" && $userInfo['email_verify_code'] != "");
    }

    public function needsAttestationLocal()
    {
        $attestationSetting = $this->getAttestationSetting();
        if ( $this->getLoginPageType() === 'none' || $attestationSetting == 0 ) {
            return false;
        }

        if ( !$this->everAttested() ) {
            return true;
        }

        if ( $attestationSetting == 2 && !$this->isUserAttestationCurrent() ) {
            return true;
        }

        return false;
    }



    public function showAttestationPage(array $userdata, string $originUrl)
    {
        $logId = $this->module->framework->log('Entra ID REDCap Authenticator: Needs Attestation', [
            "userid" => $this->username,
            "siteId" => $this->siteId
        ]);

        $site = $this->settings->getSettings($this->siteId);

        $attestationHtml         = $site['attestationText'];
        $attestationCheckboxText = $site['attestationCheckboxText'];
        $bsCssPath               = APP_PATH_WEBPACK . 'css/bootstrap.min.css';
        $bsJsPath = APP_PATH_WEBPACK . 'js/bootstrap.min.js';
        $cssPath                 = APP_PATH_CSS . 'style.css';
        $this->module->framework->initializeJavascriptModuleObject();
        $this->module->framework->tt_transferToJavascriptModuleObject();
        ?>

        <!DOCTYPE html>
        <html lang="en">

        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title><?= $this->module->framework->tt('user_attestation') ?></title>
            <link href="<?= $bsCssPath ?>" rel="stylesheet">
            <script src="<?= $bsJsPath ?>"></script>
            <link href="<?= $cssPath ?>" rel="stylesheet">
            <style>
                body {
                    height: 100%;
                    margin: 0;
                }

                div.attestation-container {
                    display: flex;
                    flex-direction: column;
                    min-height: 50%;
                    align-items: center;
                    justify-content: center;
                }

                div.attestation {
                    margin-bottom: 20px;
                }

                div.attestation-checkbox {
                    margin-bottom: 10px;
                }
            </style>
            <script src="https://code.jquery.com/jquery-3.7.1.slim.min.js"
                integrity="sha256-kmHvs0B+OpCW5GVHUNjv9rOmY0IvSIRcf7zGUDTDQM8=" crossorigin="anonymous"></script>
            <?php
            // TODO: THIS IS A WORKAROUND TO A BUG IN EM FRAMEWORK - REMOVE WHEN FIXED
            require_once APP_PATH_DOCROOT . "ExternalModules/manager/templates/hooks/every_page_top.php";
            ?>
        </head>

        <body>
            <div class="attestation-container container">
                <div class="attestation">
                    <?= $attestationHtml ?>
                </div>
                <div class="attestation-checkbox">
                    <input type="checkbox" id="attestation-checkbox" required>
                    <label for="attestation-checkbox"><?= $attestationCheckboxText ?></label>
                </div>
                <div class="attestation-submit">
                    <button id="attestation-submit-button" type="button" class="btn btn-primaryrc btn-sm"
                        disabled><?= $this->module->framework->tt('submit') ?></button>
                </div>
            </div>
        </body>

        </html>
        <script>
            document.addEventListener("DOMContentLoaded", function () {
                const module = <?= $this->module->framework->getJavascriptModuleObjectName() ?>;
                document.getElementById('attestation-submit-button').addEventListener('click', function () {
                    if (document.getElementById('attestation-checkbox').checked) {
                        module.ajax('handleAttestation', {
                            username: '<?= $userdata['username'] ?>',
                            siteId: '<?= $site['siteId'] ?>',
                            logId: '<?= $logId ?>'
                        }).then(result => {
                            if (result === true) {
                                window.location.href = decodeURIComponent("<?= urlencode($originUrl) ?>");
                            } else {
                                console.log(result);
                            }
                        });
                    }
                });
                document.getElementById('attestation-checkbox').addEventListener('change', function () {
                    document.getElementById('attestation-submit-button').disabled = !this.checked;
                });
            });
        </script>
        <?php
    }

    public static function saveAttestationVersions(array $siteIds, EntraIdAuthenticator $module)
    {
        try {
            $currentVersions     = $module->framework->getSystemSetting('entraid-attestation-version');
            $currentAttestations = $module->framework->getSystemSetting('entraid-attestation-text');
            foreach ( $siteIds as $index => $siteId ) {
                $sql                = "SELECT attestationVersion WHERE message = 'entra-id-attestation-version' AND siteId = ? ORDER BY timestamp DESC LIMIT 1";
                $param              = [ $siteId ];
                $result             = $module->framework->queryLogs($sql, $param);
                $latestSavedVersion = $result->fetch_assoc();
                $latestSavedVersion = $latestSavedVersion ? $latestSavedVersion['attestationVersion'] : 0;
                $currentVersion     = $module->framework->escape($currentVersions[$index]);

                if ( $currentVersion != $latestSavedVersion ) {
                    $currentAttestation = $module->framework->escape($currentAttestations[$index]);
                    $module->framework->log('entra-id-attestation-version', [ 'siteId' => $siteId, 'attestationVersion' => $currentVersion, 'attestation' => $currentAttestation ]);
                }
            }
        } catch ( \Throwable $e ) {
            $module->framework->log('Entra ID REDCap Authenticator: Error saving attestation versions', [ 'error' => $e->getMessage() ]);
        }
    }

    private function isUserAttestationCurrent()
    {
        if ( empty($this->username) ) {
            return false;
        }
        $attestationText = $this->module->framework->getSystemSetting($this->module::$USER_ATTESTATION_SETTING_PREFIX . $this->username);
        if ( empty($attestationText) ) {
            return false;
        }
        $attestation = json_decode($attestationText, true);
        if ( empty($attestation) || empty($attestation['siteId']) || empty($attestation['version']) ) {
            return false;
        }

        // If the user is LDAP, change the siteId to the LDAP siteId
        $userSite = $this->module->getUserType($this->username);
        if ( $userSite['authValue'] === 'local' && $userSite['siteId'] !== false ) {
            $this->siteId = $userSite['siteId'];
        }

        // Check that the site matches
        $attestationSite = $attestation['siteId'];
        if ( $attestationSite !== $this->siteId ) {
            return false;
        }

        // Check that the attestation is still valid
        $attestationVersion = $attestation['version'];
        $site               = $this->settings->getSettings($this->siteId);
        $currentVersion     = $site['attestationVersion'];
        if ( !empty($attestationVersion) && $attestationVersion !== $currentVersion ) {
            return false;
        }

        return true;
    }

    private function everAttested()
    {
        if ( empty($this->username) ) {
            return false;
        }
        $attestationText = $this->module->framework->getSystemSetting($this->module::$USER_ATTESTATION_SETTING_PREFIX . $this->username);
        if ( empty($attestationText) ) {
            return false;
        }
        return true;
    }

}