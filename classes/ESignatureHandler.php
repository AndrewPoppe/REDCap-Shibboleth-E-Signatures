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
            if ( !isset($post['esign_action']) || $post['esign_action'] !== 'save' || !isset($post['data']) ) {
                return false;
            }

            // Decrypt data
            $dataJson= decrypt($post['data']) ?? '{}';
            $data     = json_decode($dataJson, true);

            // Verify Token
            $storedToken = Authenticator::getToken();
            Authenticator::clearToken();
            if ( empty($data['token']) || strcmp($data['token'], $storedToken) !== 0 ) {
                $this->module->framework->log(ShibbolethEsignatures::MODULE_TITLE . ': Token is wrong', [
                    'postToken' => $data['token'],
                    'storedToken' => $storedToken
                ]);
                return false;
            }

            // Check if username matches
            $username     = ShibbolethEsignatures::toLowerCase($data['remoteUser']);
            $realUsername = ShibbolethEsignatures::toLowerCase($this->module->framework->getUser()->getUsername());
            if ( empty($username) || empty($realUsername) || strcmp($username, $realUsername) !== 0 ) {
                $this->module->framework->log(ShibbolethEsignatures::MODULE_TITLE . ': Usernames do not match', [
                    'username'     => $username,
                    'realUsername' => $realUsername
                ]);
                return false;
            }

            // Username associated with token matches that of logged-in REDCap user
            return true;
        } catch ( \Throwable $e ) {
            $this->module->framework->log(ShibbolethEsignatures::MODULE_TITLE . ': Error handling e-signature', [
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
                    const eventData = event.data.data;
                    const action = 'lock';
                    $.post(app_path_webroot + "Locking/single_form_action.php?pid=" + pid, {
                        auto: getParameterByName('auto'),
                        instance: getParameterByName('instance'),
                        esign_action: esign_action_global,
                        event_id: event_id,
                        action: action,
                        record: getParameterByName('id'),
                        form_name: getParameterByName('page'),
                        data: eventData
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