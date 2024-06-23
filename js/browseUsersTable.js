(() => {
    var authenticator = __MODULE__;
    var sites = JSON.parse('{{SITEDATA}}');
    const username = '{{USERNAME}}';
    const siteJson = '{{SITEJSON}}';
    function convertTableUserToEntraIdUser() {
        const username = $('#user_search').val();
        Swal.fire({
            title: authenticator.tt('convert_1'),
            input: 'select',
            inputOptions: sites,
            icon: "warning",
            showCancelButton: true,
            confirmButtonText: authenticator.tt('convert_2')
        }).then((result) => {
            console.log(result);
            if (result.isConfirmed) {
                let site = result.value;
                console.log(site);
                authenticator.ajax('convertTableUserToEntraIdUser', {
                    username: username,
                    siteId: site
                }).then(() => {
                    location.reload();
                });
            }
        });
    }

    function convertEntraIdUsertoTableUser() {
        const username = $('#user_search').val();
        Swal.fire({
            title: authenticator.tt('convert_3'),
            icon: "warning",
            showCancelButton: true,
            confirmButtonText: authenticator.tt('convert_4')
        }).then((result) => {
            if (result.isConfirmed) {
                authenticator.ajax('convertEntraIdUsertoTableUser', {
                    username: username
                }).then(() => {
                    location.reload();
                });
            }
        });
    }

    function addTableRow(siteJson) {
        const site = JSON.parse(siteJson);
        let userText = '';
        if (site['siteId'] === false) {
            switch (site['authType']) {
                case 'allowlist':
                    userText = `<strong>${authenticator.tt('user_types_1')}</strong>`;
                    break;
                case 'table':
                    userText =
                        `<strong>${authenticator.tt('user_types_2')}</strong> <input type="button" style="font-size:11px" onclick="convertTableUserToEntraIdUser()" value="Convert to Entra ID User">`;
                    break;
            }
        } else {
            userText = `<strong>${site['label']}</strong> (${site['authType']}) <input type="button" style="font-size:11px" onclick="convertEntraIdUsertoTableUser()" value="${authenticator.tt('convert_4')}">`;
        }
        $('#indv_user_info').append('<tr id="userTypeRow"><td class="data2">User type</td><td class="data2">' +
            userText + '</td></tr>');
    }

    view_user = function (username) {
        if (username.length < 1) return;
        $('#view_user_progress').css({
            'visibility': 'visible'
        });
        $('#user_search_btn').prop('disabled', true);
        $('#user_search').prop('disabled', true);
        $.get(app_path_webroot + 'ControlCenter/user_controls_ajax.php', {
            user_view: 'view_user',
            view: 'user_controls',
            username: username
        },
            function (data) {
                authenticator.ajax('getUserType', {
                    username: username
                }).then((site) => {
                    $('#view_user_div').html(data);
                    addTableRow(JSON.stringify(site));
                    enableUserSearch();
                    highlightTable('indv_user_info', 1000);
                });
            }
        );
    }

    if (username !== "") {
        window.requestAnimationFrame(() => {
            addTableRow(siteJson);
        });
    }

    $(document).ready(function () {
        if (username !== "" && !$('#userTypeRow').length) {
            view_user(username);
        }
    });
})();