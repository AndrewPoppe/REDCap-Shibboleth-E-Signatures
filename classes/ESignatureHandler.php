<?php

namespace YaleREDCap\YaleREDCapAuthenticator;

class ESignatureHandler
{
    private YaleREDCapAuthenticator $module;
    public function __construct(YaleREDCapAuthenticator $module)
    {
        $this->module = $module;
    }

    public function handleRequest(array $post)
    {
        if ( !isset($post['esign_action']) || $post['esign_action'] !== 'save' || !isset($post['token']) ) {
            return;
        }

        // Get username from token
        $authenticator = new Yale_EntraID_Authenticator($this->module);
        $userData      = $authenticator->getUserData($post['token']);
        $username      = $userData['netid'];

        // Check if username matches
        $realUsername = $this->module->framework->getUser()->getUsername();
        if ( $username !== $realUsername ) {
            $this->module->framework->log('EntraId Login E-Signature: Usernames do not match', [
                'username'     => $username,
                'realUsername' => $realUsername
            ]);
            $this->module->exitAfterHook();
            return;
        }

        global $auth_meth_global;
        $auth_meth_global = 'none';
        return;
    }

    public function addEsignatureScript()
    {
        $authType = $this->module->getUserType();
        $authenticator = new Yale_EntraID_Authenticator($this->module, $authType);
        ?>
        <script type="text/javascript" src="https://alcdn.msauth.net/browser/2.38.2/js/msal-browser.min.js"></script>
        <script>
            $(document).ready(function () {
                var numLogins = 0;
                var esign_action_global;
                const saveLockingOrig = saveLocking;
                saveLocking = function (lock_action, esign_action) {
                    if (esign_action !== 'save' || lock_action !== 1) {
                        saveLockingOrig(lock_action, esign_action);
                        return;
                    }
                    esign_action_global = esign_action;
                    const config = {
                        auth: {
                            clientId: "<?= $authenticator->getClientId() ?>",
                            authority: "https://login.microsoftonline.com/<?= $authenticator->getAdTenant() ?>",
                            redirectUri: "<?= $authenticator->getRedirectUriSpa() ?>"
                        }
                    };

                    const loginRequest = {
                        scopes: ["User.Read"],
                        prompt: "login",
                    };

                    const myMsal = new msal.PublicClientApplication(config);

                    myMsal
                        .loginPopup(loginRequest)
                        .then(function (loginResponse) {
                            const action = 'lock';
                            $.post(app_path_webroot + "Locking/single_form_action.php?pid=" + pid, {
                                auto: getParameterByName('auto'),
                                instance: getParameterByName('instance'),
                                esign_action: esign_action_global,
                                event_id: event_id,
                                action: action,
                                record: getParameterByName('id'),
                                form_name: getParameterByName('page'),
                                token: loginResponse.accessToken
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
                        })
                        .catch(function (error) {
                            console.log(error);
                        });
                }
            });
        </script>
        <?php
    }

}