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
                    at.attestation
                FROM redcap_user_information u 
                LEFT JOIN (
                    SELECT substring(`key`, 14) username, `value` entraid
                    FROM redcap_external_module_settings
                    WHERE external_module_id = ?
                    AND `key` like 'entraid-user-%'
                    ) em
                ON u.username = em.username
                LEFT JOIN (
                    SELECT substring(`key`, 21) username, `value` attestation
                    FROM redcap_external_module_settings
                    WHERE external_module_id = ?
                    AND `key` like 'entraid-attestation-%'
                    ) at
                ON u.username = at.username";
            $result = $this->module->framework->query($sql, [$this->external_module_id, $this->external_module_id]);
            $users = [];
            while ($row = $result->fetch_assoc()) {
                $row['siteId'] = $row['entraid'] === 'false' ? $this->module::$LOCAL_AUTH : $row['entraid'];
                $site = $entraidSettings[$row['siteId']] ?? $localSettings;
                $row['authType'] = $site['authValue'];
                $row['label'] = $site['label'];

                $attestation = json_decode($row['attestation'], true);
                $row['attestationSiteId'] = $attestation['siteId'];
                $row['attestationVersion'] = $attestation['version'];
                $row['attesationDate'] = $attestation['date'];
                $row['attestationText'] = html_entity_decode($attestation['attestationText']);
                $row['attestationCheckboxText'] = html_entity_decode($attestation['attestationCheckboxText']);
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
}