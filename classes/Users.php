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