<?php

namespace YaleREDCap\EntraIdAuthenticator;

class EntraIdSettings
{
    private EntraIdAuthenticator $module;
    public function __construct(EntraIdAuthenticator $module)
    {
        $this->module = $module;
    }

    public function getSettings(string $siteId)
    {
        if ( empty($siteId) ) {
            return [
                'authValue'       => $this->module::$LOCAL_AUTH,
                'label'           => 'Local',
                'loginButtonLogo' => '',
                'adTenantId'      => '',
                'clientId'        => '',
                'clientSecret'    => '',
                'redirectUrl'     => '',
                'redirectUrlSpa'  => '',
                'logoutUrl'       => '',
                'allowedGroups'   => '',
            ];
        }
        $settings = $this->getAllSettings();
        $results  = array_filter($settings, function ($setting) use ($siteId) {
            return $setting['siteId'] === $siteId;
        });
        return reset($results);
    }

    public function getSettingsByAuthValue(string $authValue)
    {
        $settings = $this->getAllSettings();
        $sites    = array_filter($settings, function ($setting) use ($authValue) {
            return $setting['authValue'] === $authValue;
        });
        return $sites[0] ?? [];
    }

    public function getAllSettings()
    {
        $settings         = [];
        $sites            = $this->module->framework->getSystemSetting('entraid-site') ?? [];
        $nSites           = count($sites);
        $siteIds          = $this->module->framework->getSystemSetting('entraid-site-id') ?? [];
        $authValues       = $this->module->framework->getSystemSetting('entraid-auth-value') ?? [];
        $labels           = $this->module->framework->getSystemSetting('entraid-label') ?? [];
        $loginButtonLogos = $this->module->framework->getSystemSetting('entraid-login-button-logo') ?? [];
        $adTenantIds      = $this->module->framework->getSystemSetting('entraid-ad-tenant-id') ?? [];
        $clientIds        = $this->module->framework->getSystemSetting('entraid-client-id') ?? [];
        $clientSsecrets   = $this->module->framework->getSystemSetting('entraid-client-secret') ?? [];
        $redirectUrls     = $this->module->framework->getSystemSetting('entraid-redirect-url') ?? [];
        $redirectUrlSpas  = $this->module->framework->getSystemSetting('entraid-redirect-url-spa') ?? [];
        $logoutUrls       = $this->module->framework->getSystemSetting('entraid-logout-url') ?? [];
        $allowedGroupss   = $this->module->framework->getSystemSetting('entraid-allowed-groups') ?? [];

        for ( $i = 0; $i < $nSites; $i++ ) {
            $settings[] = [
                'siteId'          => $siteIds[$i],
                'authValue'       => $authValues[$i],
                'label'           => $labels[$i],
                'loginButtonLogo' => $loginButtonLogos[$i],
                'adTenantId'      => $adTenantIds[$i],
                'clientId'        => $clientIds[$i],
                'clientSecret'    => $clientSsecrets[$i],
                'redirectUrl'     => $redirectUrls[$i],
                'redirectUrlSpa'  => $redirectUrlSpas[$i],
                'logoutUrl'       => $logoutUrls[$i],
                'allowedGroups'   => $allowedGroupss[$i],
            ];
        }
        return $settings;
    }

    public function getAuthValues()
    {
        $values = $this->module->framework->getSystemSetting('entraid-auth-value');
        return array_filter($values, function ($value) {
            return $value !== $this->module::$LOCAL_AUTH;
        });
    }

    public function getSiteInfo()
    {
        $settings = $this->getAllSettings();
        return array_map(function ($setting) {
            return [
                'siteId'   => $setting['siteId'],
                'label'    => $setting['label'],
                'authType' => $setting['authValue'],
            ];
        }, $settings);
    }

}