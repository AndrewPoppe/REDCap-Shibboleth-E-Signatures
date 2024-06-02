<?php

namespace YaleREDCap\EntraIdAuthenticator;

class EntraIdSettings
{
    private EntraIdAuthenticator $module;
    public function __construct(EntraIdAuthenticator $module)
    {
        $this->module = $module;
    }

    public function getSettings(string $authValue)
    {
        if ( $authValue === $this->module::$LOCAL_AUTH) {
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
        return array_filter($settings, function ($setting) use ($authValue) {
            return $setting['authValue'] === $authValue;
        })[0];
    }

    public function getAllSettings()
    {
        $settings         = [];
        $sites            = $this->module->framework->getSystemSetting('entraid-site') ?? [];
        $nSites           = count($sites);
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
            $auth = $authValues[$i];
            $settings[] = [
                'authValue'       => $auth,
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

}