<?php

namespace YaleREDCap\ShibbolethEsignatures;

/**
 * @property \ExternalModules\Framework $framework
 * @see Framework
 */

require_once 'classes/Authenticator.php';
require_once 'classes/ESignatureHandler.php';

class ShibbolethEsignatures extends \ExternalModules\AbstractExternalModule
{

    const MODULE_TITLE = 'Shibboleth E-Signatures';

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
                
                // This only applies to non-table-based users
                if ( \Authentication::isTableUser($userid) ) {
                    return;
                }

                // Let REDCap handle all requests that aren't saving esignatures
                if ( $_POST['esign_action'] !== 'save') {
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

            // Store Shibboleth Information
            Authenticator::storeShibbolethInformation();

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
     * REDCap Hook
     * @return mixed
     */
    public function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
    {
        if ($action === 'setEsignFlag') {
            return Authenticator::setEsignRequestTimestamp();
        }
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