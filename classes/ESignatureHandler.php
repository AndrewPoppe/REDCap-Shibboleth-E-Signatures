<?php

namespace YaleREDCap\ShibbolethEsignatures;

class ESignatureHandler
{
    private ShibbolethEsignatures $module;
    public function __construct(ShibbolethEsignatures $module)
    {
        $this->module = $module;
    }

    /**
     * Do E-Signature
     * @param array $post
     * @return bool
     */
    public function handleRequest(array $post)
    {
        try {
            if ( !isset($post['esign_action']) || $post['esign_action'] !== 'save' || !isset($post['token']) ) {
                return false;
            }

            // Verify Token
            $storedToken = Authenticator::getToken();
            Authenticator::clearToken();
            if ( empty($post['token']) || strcmp($post['token'], $storedToken) !== 0 ) {
                $this->module->framework->log('Shibboleth E-Signatures: Token is wrong', [
                    'postToken' => $post['token'],
                    'storedToken' => $storedToken
                ]);
                return false;
            }

            // Check if username matches
            $username     = ShibbolethEsignatures::toLowerCase($post['remoteUser']);
            $realUsername = ShibbolethEsignatures::toLowerCase($this->module->framework->getUser()->getUsername());
            if ( empty($username) || empty($realUsername) || strcmp($username, $realUsername) !== 0 ) {
                $this->module->framework->log('Shibboleth E-Signatures: Usernames do not match', [
                    'username'     => $username,
                    'realUsername' => $realUsername
                ]);
                return false;
            }

            // Username associated with token matches that of logged-in REDCap user
            return true;
        } catch ( \Throwable $e ) {
            $this->module->framework->log('Shibboleth E-Signatures: Error handling e-signature', [
                'username'     => $username,
                'realUsername' => $realUsername
            ]);
            return false;
        }
    }

    public function addEsignatureScript()
    {
        echo $this->module->framework->initializeJavascriptModuleObject();

        ?>
        <script>
            $(document).ready(function () {
                var module = <?=$this->module->framework->getJavascriptModuleObjectName()?>;
                var numLogins = 0;
                var esign_action_global;
                const saveLockingOrig = saveLocking;

                window.addEventListener('message', (event) => {
                    if (event.origin !== window.origin) {
                        return;
                    }
                    const remoteUser = event.data.user;
                    const token = event.data.token;
                    const action = 'lock';
                    $.post(app_path_webroot + "Locking/single_form_action.php?pid=" + pid, {
                        auto: getParameterByName('auto'),
                        instance: getParameterByName('instance'),
                        esign_action: esign_action_global,
                        event_id: event_id,
                        action: action,
                        record: getParameterByName('id'),
                        form_name: getParameterByName('page'),
                        remoteUser: remoteUser,
                        token: token
                    }, function (data) {
                        if (data != "") {
                            numLogins = 0;
                            if (auto_inc_set && getParameterByName('auto') == '1' && isinteger(data.replace(
                                '-', ''))) {
                                $('#form :input[name="' + table_pk + '"], #form :input[name="__old_id__"]')
                                    .val(data);
                            }
                            formSubmitDataEntry();
                        } else {
                            numLogins++;
                            esignFail(numLogins);
                        }
                    });
                }, false);

                saveLocking = function (lock_action, esign_action) {
                    if (esign_action !== 'save' || lock_action !== 1) {
                        saveLockingOrig(lock_action, esign_action);
                        return;
                    }
                    esign_action_global = esign_action;

                    module.ajax('setEsignFlag', {})
                    .then(function(response) {
                        window.open(module.getUrl('esign.php'), '_blank', 'popup');
                    });
                }
            });
        </script>
        <?php
    }

}