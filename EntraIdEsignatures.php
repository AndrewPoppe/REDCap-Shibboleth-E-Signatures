<?php

namespace YaleREDCap\EntraIdEsignatures;

/**
 * @property \ExternalModules\Framework $framework
 * @see Framework
 */

require_once 'classes/Authenticator.php';
require_once 'classes/ESignatureHandler.php';

class EntraIdEsignatures extends \ExternalModules\AbstractExternalModule
{

    const MODULE_TITLE = 'EntraId E-Signatures';

    /**
     * REDCap Hook
     * @param mixed $project_id
     * @return void
     */
    public function redcap_every_page_before_render($project_id = null)
    {
        try {
            global $userid, $shibboleth_esign_salt;

            // Defining this global allows all users to be capable of being granted e-signature user rights and of 
            // performing e-signatures
            $shibboleth_esign_salt = 'NULL';

            // Check if we're in a page that needs to be handled
            $page = defined('PAGE') ? PAGE : null;
            if ( empty($page) ) {
                return;
            }

            // Don't do anything for SYSTEM user
            if ( defined('USERID') && USERID === 'SYSTEM' ) {
                return;
            }

            // Handle E-Signature form action
            if ( $page === 'Locking/single_form_action.php' && $_SERVER['REQUEST_METHOD'] === 'POST' ) {
                if ( \Authentication::isTableUser($userid) ) {
                    return;
                }
                $esignatureHandler = new ESignatureHandler($this);
                $result            = $esignatureHandler->handleRequest($_POST);

                // Either there was an error handling the request or the credentials did not match
                if ( empty($result) || !$result ) {
                    $this->framework->exitAfterHook();
                    return;
                }

                // Credentials match - setting auth_meth_global here to 'none' allows the e-signature to happen
                // This is okay, because the user has already been re-authenticated above
                global $auth_meth_global;
                $auth_meth_global = 'none';
                return;
            }

        } catch ( \Throwable $e ) {
            $this->framework->log(self::MODULE_TITLE . ': Error', [ 'error' => $e->getMessage() ]);
        }

    }

    /**
     * REDCap Hook
     * @return void
     */
    public function redcap_data_entry_form()
    {
        try {
            $username = $this->framework->getUser()->getUsername();
            if ( \Authentication::isTableUser($username) ) {
                return;
            }
            $esignatureHandler = new ESignatureHandler($this);
            $esignatureHandler->addEsignatureScript();
        } catch ( \Throwable $e ) {
            $this->framework->log(self::MODULE_TITLE . ': Error adding ESignature script', [ 'error' => $e->getMessage() ]);
        }
    }

    /**
     * Return array of module's system settings
     * @return array{adTenantId: string|null, clientId: string|null, clientSecret: string|null, redirectUrlSpa: string|null, adUsernameAttribute: string|null} 
     */
    public function getSettings() : array
    {
        $settings = [];
        try {
            $settings['adTenantId']          = $this->framework->getSystemSetting('entraid-ad-tenant-id') ?? '';
            $settings['clientId']            = $this->framework->getSystemSetting('entraid-client-id') ?? '';
            $settings['clientSecret']        = $this->framework->getSystemSetting('entraid-client-secret') ?? '';
            $settings['redirectUrlSpa']      = $this->framework->getSystemSetting('entraid-redirect-url-spa') ?? '';
            $settings['adUsernameAttribute'] = $this->framework->getSystemSetting('entraid-ad-username-attribute') ?? '';
        } catch ( \Throwable $e ) {
            $this->framework->log(self::MODULE_TITLE . ': Error getting settings', [ 'error' => $e->getMessage() ]);
        }
        return $settings;
    }

    /**
     * Return lower-case version of string input
     * @param string $string
     * @return string
     */
    public static function toLowerCase(string $string) : string
    {
        if ( extension_loaded('mbstring') ) {
            return mb_strtolower($string);
        }
        return strtolower($string);
    }
}