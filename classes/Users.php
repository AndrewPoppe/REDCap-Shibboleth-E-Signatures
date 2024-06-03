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
            $entraidSettings = $settings->getAllSettings();
            $sql = "SELECT 
                    u.username, 
                    u.user_firstname,
                    u.user_lastname,
                    u.user_email,
                    em.entraid
                FROM redcap_user_information u 
                LEFT JOIN (
                    SELECT substring(`key`, 14) username, `value` entraid
                    FROM redcap_external_module_settings
                    WHERE external_module_id = ?
                    AND `key` like 'entraid-user-%'
                    ) em
                ON u.username = em.username";
            $result = $this->module->framework->query($sql, [$this->external_module_id]);
            $users = [];
            while ($row = $result->fetch_assoc()) {
                $row['siteId'] = $row['entraid'];
                $site = array_filter($entraidSettings, function ($setting) use ($row) {
                    return $setting['siteId'] === $row['siteId'];
                });
                $site = reset($site);
                $row['authType'] = $site['authValue'];
                $row['label'] = $site['label'];
                $users[] = $row;
            }
            return $users;
        } catch (\Exception $e) {
            return [];
        }
    }

    public function getUserData($userId)
    {
        try {
            $sql = "SELECT 
                    u.username, 
                    u.user_firstname,
                    u.user_lastname,
                    u.user_email,
                    em.entraid
                FROM redcap_user_information u 
                LEFT JOIN (
                    SELECT substring(`key`, 14) username, `value` entraid
                    FROM redcap_external_module_settings
                    WHERE external_module_id = ?
                    AND `key` like 'entraid-user-%'
                    ) em
                ON u.username = em.username";
            $result = $this->module->framework->query($sql, [$this->external_module_id]);
            $users = [];
            while ($row = $result->fetch_assoc()) {
                $userid = $row['username'];
                $users[] = $row;
            }
            return $users;
        } catch (\Exception $e) {
            return [];
        }
    }
}