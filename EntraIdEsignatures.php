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
            $this->framework->log('EntraId E-Signatures: Error', [ 'error' => $e->getMessage() ]);
        }

    }

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
            $this->framework->log('Error adding ESignature script', [ 'error' => $e->getMessage() ]);
        }
    }

    public function getSettings()
    {
        return [
            'adTenantId'          => $this->framework->getSystemSetting('entraid-ad-tenant-id') ?? '',
            'clientId'            => $this->framework->getSystemSetting('entraid-client-id') ?? '',
            'clientSecret'        => $this->framework->getSystemSetting('entraid-client-secret') ?? '',
            'redirectUrlSpa'      => $this->framework->getSystemSetting('entraid-redirect-url-spa') ?? '',
            'adUsernameAttribute' => $this->framework->getSystemSetting('entraid-ad-username-attribute') ?? ''
        ];
    }

    public static function toLowerCase(string $string) : string
    {
        if ( extension_loaded('mbstring') ) {
            return mb_strtolower($string);
        }
        return strtolower($string);
    }
}