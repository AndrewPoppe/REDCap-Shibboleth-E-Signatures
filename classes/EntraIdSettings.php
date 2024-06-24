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
        if ( empty($siteId) || $siteId === EntraIdAuthenticator::LOCAL_AUTH ) {
            return [
                'authValue'               => EntraIdAuthenticator::LOCAL_AUTH,
                'siteId'                  => EntraIdAuthenticator::LOCAL_AUTH,
                'label'                   => 'Local',
                'domain'                  => '',
                'loginButtonLogo'         => '',
                'adTenantId'              => '',
                'clientId'                => '',
                'clientSecret'            => '',
                'redirectUrl'             => '',
                'redirectUrlSpa'          => '',
                'logoutUrl'               => '',
                'allowedGroups'           => '',
                'showAttestation'         => $this->module->getSystemSetting('entraid-attestation-default') ?? '',
                'attestationText'         => \REDCap::filterHtml($this->module->getSystemSetting('entraid-attestation-text-default') ?? ''),
                'attestationCheckboxText' => \REDCap::filterHtml($this->module->getSystemSetting('entraid-attestation-checkbox-text-default') ?? ''),
                'attestationVersion'      => $this->module->getSystemSetting('entraid-attestation-version-default') ?? '',
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

        if ( empty($authValue) || $authValue === EntraIdAuthenticator::LOCAL_AUTH ) {
            return $this->getSettings(EntraIdAuthenticator::LOCAL_AUTH);
        }

        $settings = $this->getAllSettings();
        $sites    = array_filter($settings, function ($setting) use ($authValue) {
            return $setting['authValue'] === $authValue;
        });
        return reset($sites) ?? [];
    }

    public function getAllSettings()
    {
        $settings                = [];
        $sites                   = $this->module->framework->getSystemSetting('entraid-site') ?? [];
        $nSites                  = count($sites);
        $siteIds                 = $this->module->framework->getSystemSetting('entraid-site-id') ?? [];
        $authValues              = $this->module->framework->getSystemSetting('entraid-auth-value') ?? [];
        $labels                  = $this->module->framework->getSystemSetting('entraid-label') ?? [];
        $domains                 = $this->module->framework->getSystemSetting('entraid-domain') ?? [];
        $loginButtonLogos        = $this->module->framework->getSystemSetting('entraid-login-button-logo') ?? [];
        $adTenantIds             = $this->module->framework->getSystemSetting('entraid-ad-tenant-id') ?? [];
        $clientIds               = $this->module->framework->getSystemSetting('entraid-client-id') ?? [];
        $clientSsecrets          = $this->module->framework->getSystemSetting('entraid-client-secret') ?? [];
        $redirectUrls            = $this->module->framework->getSystemSetting('entraid-redirect-url') ?? [];
        $redirectUrlSpas         = $this->module->framework->getSystemSetting('entraid-redirect-url-spa') ?? [];
        $logoutUrls              = $this->module->framework->getSystemSetting('entraid-logout-url') ?? [];
        $allowedGroupss          = $this->module->framework->getSystemSetting('entraid-allowed-groups') ?? [];
        $showAttestation         = $this->module->framework->getSystemSetting('entraid-attestation') ?? [];
        $attestationText         = $this->module->framework->getSystemSetting('entraid-attestation-text') ?? [];
        $attestationCheckboxText = $this->module->framework->getSystemSetting('entraid-attestation-checkbox-text') ?? [];
        $attestationVersion      = $this->module->framework->getSystemSetting('entraid-attestation-version') ?? [];

        for ( $i = 0; $i < $nSites; $i++ ) {
            $settings[] = [
                'siteId'                  => $siteIds[$i],
                'authValue'               => $this->module->framework->escape($authValues[$i]),
                'label'                   => $this->module->framework->escape($labels[$i]),
                'domain'                  => urlencode($domains[$i]),
                'loginButtonLogo'         => $loginButtonLogos[$i],
                'adTenantId'              => $adTenantIds[$i],
                'clientId'                => $clientIds[$i],
                'clientSecret'            => $clientSsecrets[$i],
                'redirectUrl'             => $redirectUrls[$i],
                'redirectUrlSpa'          => $redirectUrlSpas[$i],
                'logoutUrl'               => $logoutUrls[$i],
                'allowedGroups'           => $allowedGroupss[$i],
                'showAttestation'         => $showAttestation[$i],
                'attestationText'         => \REDCap::filterHtml($attestationText[$i] ?? $this->module->getSystemSetting('entraid-attestation-text-default') ?? ''),
                'attestationCheckboxText' => \REDCap::filterHtml($attestationCheckboxText[$i] ?? $this->module->getSystemSetting('entraid-attestation-checkbox-text-default') ?? ''),
                'attestationVersion'      => $attestationVersion[$i] ?? $this->module->getSystemSetting('entraid-attestation-version-default') ?? '',
            ];
        }
        return $settings;
    }

    public function getAllSettingsWithSiteIdIndex()
    {
        $settings = $this->getAllSettings();
        return array_reduce($settings, function ($acc, $setting) {
            $acc[$setting['siteId']] = $setting;
            return $acc;
        }, []);
    }

    public function getAuthValues()
    {
        $values = $this->module->framework->getSystemSetting('entraid-auth-value');
        return array_filter($values, function ($value) {
            return $value !== EntraIdAuthenticator::LOCAL_AUTH;
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