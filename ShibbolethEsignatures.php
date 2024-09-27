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
    const MAX_REQUEST_AGE_SECONDS = 300;
    const IDP_LOGOUT_REDIRECT_PLACEHOLDER = '{REDIRECT}';
    const IDP_LOGOUT_COOKIE = 'IDP-LOGOUT-INITIATED';

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
            $shibboleth_esign_salt = $shibboleth_esign_salt ?? 'NULL';

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
            $onESignaturePage = $page === 'Locking/single_form_action.php';
            $isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
            $isNotTableUser = !\Authentication::isTableUser($userid);
            $isEsignSave = $_POST['esign_action'] === 'save';
            if ( $onESignaturePage && $isPost && $isNotTableUser && $isEsignSave ) {

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

            echo '<pre>';
            var_dump(Authenticator::getIdPEntityId());
            var_dump($this->getIdPLogoutUrl());
            var_dump($_SERVER);
            echo '</pre>';

            $username = $this->framework->getUser()->getUsername();
            if ( \Authentication::isTableUser($username) ) {
                return;
            }
            $esignatureHandler = new ESignatureHandler($this);
            $esignatureHandler->addEsignatureScript();

            // Clear Timestamp if necessary
            Authenticator::clearEsignRequestTimestamp();

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
        if ( $action === 'setEsignFlag' ) {
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

    public function getIdPLogoutUrl()
    {
        $entityId = Authenticator::getIdPEntityId();
        $idps = $this->framework->getSubSettings('idp-logout');

        $matched_idp = array_filter($idps, function($idp) use ($entityId) {
            return $idp['idp-logout-entityid'] === $entityId;
        }, );

        if (sizeof($matched_idp) === 0) {
            return '';
        }

        $matched_idp = reset($matched_idp);
        $url = $matched_idp['idp-logout-url'];
        return str_replace(self::IDP_LOGOUT_REDIRECT_PLACEHOLDER, urlencode($this->framework->getUrl('esign.php')), $url);

    }
}