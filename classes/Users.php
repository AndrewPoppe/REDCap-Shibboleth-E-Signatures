<?php 
namespace YaleREDCap\EntraIdAuthenticator;

class Users
{
    private EntraIdAuthenticator $module;
    private $external_module_id;
    public function __construct(EntraIdAuthenticator $module)
    {
        $this->module = $module;
        $this->external_module_id = \ExternalModules\ExternalModules::getIdForPrefix($module->PREFIX);
    }

    public function getAllUserData()
    {
        try {
            $settings = new EntraIdSettings($this->module);
            $entraidSettings = $settings->getAllSettingsWithSiteIdIndex();
            $localSettings = $settings->getSettings($this->module::$LOCAL_AUTH);
            $sql = "SELECT 
                    u.username, 
                    u.user_firstname,
                    u.user_lastname,
                    u.user_email,
                    em.entraid,
                    at.attestationVersion,
                    at.attestationSiteId,
                    at.attestationDate,
                    at.attestationText,
                    at.attestationCheckboxText,
                    pr.ui_id IS NOT NULL passwordResetNeeded
                FROM redcap_user_information u 
                LEFT JOIN (
                    SELECT substring(`key`, 14) username, `value` entraid
                    FROM redcap_external_module_settings
                    WHERE external_module_id = ?
                    AND `key` LIKE '".$this->module::$USER_TYPE_SETTING_PREFIX."%'
                    ) em
                ON u.username = em.username
                LEFT JOIN (
                    SELECT substring(`key`, 21) username, 
                        IF(JSON_VALID(`value`), JSON_UNQUOTE(JSON_EXTRACT(`value`, '$.version')), NULL) attestationVersion,
                        IF(JSON_VALID(`value`), JSON_UNQUOTE(JSON_EXTRACT(`value`, '$.siteId')), NULL) attestationSiteId,
                        IF(JSON_VALID(`value`), JSON_UNQUOTE(JSON_EXTRACT(`value`, '$.date')), NULL) attestationDate,
                        IF(JSON_VALID(`value`), JSON_UNQUOTE(JSON_EXTRACT(`value`, '$.attestationText')), NULL) attestationText,
                        IF(JSON_VALID(`value`), JSON_UNQUOTE(JSON_EXTRACT(`value`, '$.attestationCheckboxText')), NULL) attestationCheckboxText
                    FROM redcap_external_module_settings
                    WHERE external_module_id = ?
                    AND `key` LIKE '".$this->module::$USER_ATTESTATION_SETTING_PREFIX."%'
                    ) at
                ON u.username = at.username
                LEFT JOIN redcap_user_information i
                on u.username = i.username
                LEFT JOIN (
                    SELECT ui_id
                    FROM redcap_external_modules_log
                    WHERE external_module_id = ?
                    AND message = 'password-reset-needed'
                    ) pr
                ON i.ui_id= pr.ui_id";
            $result = $this->module->framework->query($sql, [$this->external_module_id, $this->external_module_id, $this->external_module_id]);
            $users = [];
            while ($row = $result->fetch_assoc()) {
                $row['siteId'] = $row['entraid'] === 'false' ? $this->module::$LOCAL_AUTH : $row['entraid'];
                $site = $entraidSettings[$row['siteId']] ?? $localSettings;
                $row['authType'] = $site['authValue'];
                $row['label'] = $site['label'];

                $attestationSite = $entraidSettings[$row['attestationSiteId']] ?? $localSettings;
                $row['attestationSiteLabel'] = $attestationSite['label'];

                $AttestationSiteMatches    = $site['siteId'] === $row['attestationSiteId'];
                $AttestationVersionMatches = $site['attestationVersion'] === $row['attestationVersion'];
                $row['attestationCurrent'] = $AttestationSiteMatches && $AttestationVersionMatches;

                $users[] = $row;
            }
            return $users;
        } catch (\Exception $e) {
            return [];
        }
    }

    public function deleteUser($username) {
        if (!(SUPER_USER || ACCOUNT_MANAGER)) {
            return;
        }
        if (empty($username) || !$this->module->userExists($username)) {
            return;
        }
        if (ACCOUNT_MANAGER && $this->module->framework->getUser($username)->isSuperUser()) {
            return;
        }
        $SQL = "DELETE FROM redcap_external_module_settings
                WHERE external_module_id = ?
                AND project_id IS NULL
                AND `key` IN (?, ?)";
        $params = [
            $this->external_module_id, 
            $this->module::$USER_TYPE_SETTING_PREFIX . $username, 
            $this->module::$USER_ATTESTATION_SETTING_PREFIX . $username
        ];
        return $this->module->framework->query($SQL, $params);
    }

    public function getUsers(string $siteId) {
        try {
            $users = [];
            if ( empty($siteId) ) {
                return $users;
            }
            $SQL    = "SELECT SUBSTRING(`key`, 14) username 
                    FROM redcap_external_module_settings 
                    WHERE external_module_id = ?
                    AND `key` LIKE '" . $this->module::$USER_TYPE_SETTING_PREFIX . "%'
                    AND `value` = ?";
            $params = [ $this->external_module_id, $siteId ];
            $result = $this->module->framework->query($SQL, $params);
            while ( $row = $result->fetch_assoc() ) {
                $users[] = $row['username'];
            }
            return $users;
        } catch (\Throwable $e) {
            $this->module->framework->log('Error getting users', [ 'siteId'=> $this->module->framework->escape($siteId), 'error' => $e->getMessage() ]);
            return;
        }
    }
}