<?php 
namespace YaleREDCap\EntraIdAuthenticator;

class Users
{
    private EntraIdAuthenticator $module;
    private $externalModuleId;
    public function __construct(EntraIdAuthenticator $module)
    {
        $this->module = $module;
        $this->externalModuleId = \ExternalModules\ExternalModules::getIdForPrefix($module->PREFIX);
    }

    public function getAllUserData()
    {
        try {
            $settings = new EntraIdSettings($this->module);
            $entraidSettings = $settings->getAllSettingsWithSiteIdIndex();
            $localSettings = $settings->getSettings(EntraIdAuthenticator::LOCAL_AUTH);
            $sql = "SELECT 
                    u.username, 
                    u.user_firstname,
                    u.user_lastname,
                    u.user_email,
                    u.user_suspended_time,
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
                    AND `key` LIKE '".EntraIdAuthenticator::USER_TYPE_SETTING_PREFIX."%'
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
                    AND `key` LIKE '".EntraIdAuthenticator::USER_ATTESTATION_SETTING_PREFIX."%'
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
            $result = $this->module->framework->query($sql, [$this->externalModuleId, $this->externalModuleId, $this->externalModuleId]);
            $users = [];
            while ($row = $result->fetch_assoc()) {
                $row['siteId'] = $row['entraid'] === 'false' ? EntraIdAuthenticator::LOCAL_AUTH : $row['entraid'];
                $site = $entraidSettings[$row['siteId']] ?? $localSettings;
                $row['authType'] = $site['authValue'];
                $row['label'] = $site['label'];

                $attestationSite = $entraidSettings[$row['attestationSiteId']] ?? $localSettings;
                $row['attestationSiteLabel'] = $attestationSite['label'];

                $attestationSiteMatches    = $site['siteId'] === $row['attestationSiteId'];
                $attestationVersionMatches = $site['attestationVersion'] === $row['attestationVersion'];
                $row['attestationCurrent'] = $attestationSiteMatches && $attestationVersionMatches;

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
        if (empty($username) || !$this->userExists($username)) {
            return;
        }
        if (ACCOUNT_MANAGER && $this->module->framework->getUser($username)->isSuperUser()) {
            return;
        }
        $sql = "DELETE FROM redcap_external_module_settings
                WHERE external_module_id = ?
                AND project_id IS NULL
                AND `key` IN (?, ?)";
        $params = [
            $this->externalModuleId, 
            EntraIdAuthenticator::USER_TYPE_SETTING_PREFIX . $username, 
            EntraIdAuthenticator::USER_ATTESTATION_SETTING_PREFIX . $username
        ];
        return $this->module->framework->query($sql, $params);
    }

    public function getUsers(string $siteId) {
        try {
            $users = [];
            if ( empty($siteId) ) {
                return $users;
            }
            $sql    = "SELECT SUBSTRING(`key`, 14) username 
                    FROM redcap_external_module_settings 
                    WHERE external_module_id = ?
                    AND `key` LIKE '" . EntraIdAuthenticator::USER_TYPE_SETTING_PREFIX . "%'
                    AND `value` = ?";
            $params = [ $this->externalModuleId, $siteId ];
            $result = $this->module->framework->query($sql, $params);
            while ( $row = $result->fetch_assoc() ) {
                $users[] = $row['username'];
            }
            return $users;
        } catch (\Throwable $e) {
            $this->module->framework->log('Error getting users', [ 'siteId'=> $this->module->framework->escape($siteId), 'error' => $e->getMessage() ]);
            return;
        }
    }

    public function convertTableUserToEntraIdUser(string $username, string $siteId)
    {
        if ( empty($username) ) {
            return;
        }
        try {
            $sql   = 'DELETE FROM redcap_auth WHERE username = ?';
            $query = $this->module->framework->query($sql, [ $username ]);
            $this->setEntraIdUser($username, $siteId);
            return;
        } catch ( \Exception $e ) {
            $this->module->framework->log('Entra ID REDCap Authenticator: Error converting table user to YALE user', [ 'error' => $e->getMessage() ]);
            return;
        }
    }

    public function convertTableUsersToEntraIdUsers(array $usernames, string $siteId)
    {
        if ( empty($usernames) ) {
            return;
        }
        try {
            $questionMarks = [];
            $params        = [];
            foreach ( $usernames as $username ) {
                $questionMarks[] = '?';
                $params[]        = $username;
            }
            $sql    = 'DELETE FROM redcap_auth WHERE username in (' . implode(',', $questionMarks) . ')';
            $result = $this->module->framework->query($sql, $params);
            if ( $result ) {
                foreach ( $usernames as $username ) {
                    $this->setEntraIdUser($username, $siteId);
                }
            }
            return;
        } catch ( \Exception $e ) {
            $this->module->framework->log('Entra ID REDCap Authenticator: Error converting table user to YALE user', [ 'error' => $e->getMessage() ]);
            return;
        }
    }

    public function convertEntraIdUsertoTableUser(string $username)
    {
        if ( empty($username) ) {
            return;
        }
        if ( !$this->isEntraIdUser($username) ) {
            return false;
        }
        try {
            $sql   = "INSERT INTO redcap_auth (username) VALUES (?)";
            $query = $this->module->framework->query($sql, [ $username ]);
            \Authentication::resetPasswordSendEmail($username);
            $this->setEntraIdUser($username, false);
            return;
        } catch ( \Exception $e ) {
            $this->module->framework->log('Entra ID REDCap Authenticator: Error converting YALE user to table user', [ 'error' => $e->getMessage() ]);
            return;
        }
    }

    public function convertEntraIdUserstoTableUsers(array $usernames)
    {
        if ( empty($usernames) ) {
            return;
        }
        try {
            $questionMarks0 = [];
            $questionMarks  = [];
            $params         = [];
            foreach ( $usernames as $username ) {
                $questionMarks0[] = '?';
                $questionMarks[]  = '(?)';
                $params[]         = $username;
            }

            $testSQL = 'SELECT count(*) n FROM redcap_auth WHERE username IN (' . implode(',', $questionMarks0) . ')';
            $testQ   = $this->module->framework->query($testSQL, $params);
            $testRow = $testQ->fetch_assoc();
            if ( $testRow['n'] > 0 ) {
                return false;
            }

            $sql    = 'INSERT INTO redcap_auth (username) VALUES ' . implode(',', $questionMarks);
            $result = $this->module->framework->query($sql, $params);
            foreach ( $usernames as $username ) {
                $this->module->framework->log('password-reset-needed', [ 'username' => $username, 'username_to_reset' => $username ]);
            }
            return;
        } catch ( \Exception $e ) {
            $this->module->framework->log('Entra ID REDCap Authenticator: Error converting YALE user to table user', [ 'error' => $e->getMessage() ]);
            return;
        }
    }

    public function createUser($username, $userdata)
    {
        try {
            if (
                isset($userdata['user_firstname']) &&
                isset($userdata['user_lastname']) &&
                isset($userdata['user_email'])
            ) {
                $this->setUserDetails($username, $userdata);
                return true;
            }
            return false;
        } catch ( \Throwable $e ) {
            $this->module->framework->log('Entra ID REDCap Authenticator: Error creating user', [ 'error' => $e->getMessage() ]);
            return false;
        }
    }

    /**
     * @param string $username
     * @return bool
     */
    public function inUserAllowlist(string $username)
    {
        $sql = "SELECT 1 FROM redcap_user_allowlist WHERE username = ?";
        $q   = $this->module->framework->query($sql, [ $username ]);
        return $q->fetch_assoc() !== null;
    }

    private function setUserDetails($username, $details)
    {
        if ( $this->userExists($username) ) {
            $this->updateUserDetails($username, $details);
        } else {
            $this->insertUserDetails($username, $details);
        }
    }

    public function userExists($username)
    {
        $sql = 'SELECT 1 FROM redcap_user_information WHERE username = ?';
        $q   = $this->module->framework->query($sql, [ $username ]);
        return $q->fetch_assoc() !== null;
    }

    private function updateUserDetails($username, $details)
    {
        try {
            $sql    = 'UPDATE redcap_user_information SET user_firstname = ?, user_lastname = ?, user_email = ? WHERE username = ?';
            $params = [ $details['user_firstname'], $details['user_lastname'], $details['user_email'], $username ];
            $query  = $this->module->framework->createQuery();
            $query->add($sql, $params);
            $query->execute();
            return $query->affected_rows;
        } catch ( \Exception $e ) {
            $this->module->framework->log('Yale Authenticator: Error updating user details', [ 'error' => $e->getMessage() ]);
        }
    }

    private function insertUserDetails($username, $details)
    {
        try {
            $sql    = 'INSERT INTO redcap_user_information (username, user_firstname, user_lastname, user_email, user_creation) VALUES (?, ?, ?, ?, ?)';
            $params = [ $username, $details['user_firstname'], $details['user_lastname'], $details['user_email'], NOW ];
            $query  = $this->module->framework->createQuery();
            $query->add($sql, $params);
            $query->execute();
            return $query->affected_rows;
        } catch ( \Exception $e ) {
            $this->module->framework->log('Yale Authenticator: Error inserting user details', [ 'error' => $e->getMessage() ]);
        }
    }

    public function isEntraIdUser($username)
    {
        return !\Authentication::isTableUser($username) &&
            !empty($this->module->framework->getSystemSetting(EntraIdAuthenticator::USER_TYPE_SETTING_PREFIX . $username)) &&
            $this->module->framework->getSystemSetting(EntraIdAuthenticator::USER_TYPE_SETTING_PREFIX . $username) !== "false";
    }

    /**
     * Summary of getUserType
     * @param mixed $username
     * @return array{siteId: string|false, authValue: string, authType: string, label: string} 
     */
    public function getUserType($username = null) : array
    {
        if ( $username === null ) {
            $username = $this->module->getUserId();
        }
        $siteId = $this->module->framework->getSystemSetting(EntraIdAuthenticator::USER_TYPE_SETTING_PREFIX . $username);
        if ( $siteId && $siteId !== 'false' ) {
            $site = (new EntraIdSettings($this->module))->getSettings($siteId);
            return [
                'siteId'    => $siteId,
                'authValue' => $site['authValue'],
                'authType'  => $site['authValue'],
                'label'     => $site['label']
            ];
        }
        if ( \Authentication::isTableUser($username) ) {
            return [
                'siteId'    => false,
                'authValue' => 'local',
                'authType'  => 'table',
                'label'     => 'Table User'
            ];
        }
        if ( $this->inUserAllowlist($username) ) {
            return [
                'siteId'    => false,
                'authValue' => 'local',
                'authType'  => 'allowlist',
                'label'     => 'Allowlisted User'
            ];
        }
        return [
            'siteId'    => false,
            'authValue' => 'local',
            'authType'  => 'unknown',
            'label'     => 'Unknown'
        ];
    }

    public function setEntraIdUser($username, $value)
    {
        $this->module->framework->setSystemSetting(EntraIdAuthenticator::USER_TYPE_SETTING_PREFIX . $username, $value);
    }

    public function checkAllowlist($username)
    {
        global $enable_user_allowlist;
        return !$enable_user_allowlist || \Authentication::isTableUser($username) || $this->inUserAllowlist($username) || $username === 'SYSTEM';
    }
}