<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

$module->framework->initializeJavascriptModuleObject();
$module->framework->tt_transferToJavascriptModuleObject();
$settings = new EntraIdSettings($module);
$siteInfo = $settings->getSiteInfo();

?>
<link href="https://cdn.datatables.net/v/dt/jszip-3.10.1/dt-2.0.8/b-3.0.2/b-html5-3.0.2/sl-2.0.3/datatables.min.css" rel="stylesheet">
<script src="https://cdn.datatables.net/v/dt/jszip-3.10.1/dt-2.0.8/b-3.0.2/b-html5-3.0.2/sl-2.0.3/datatables.min.js"></script>
<style>
table.dataTable#users-table tbody tr.selected>*,
table.dataTable#users-table tbody tr.selected:hover>* {
    box-shadow: inset 0 0 0 9999px rgba(255, 0, 108, 0.15) !important;
    border-top-color: rgba(0, 0, 0, 0.15);
    color: currentColor !important;
}
#pagecontainer {
    max-width: 100%;
}
</style>
<div class="container">
    <div class="d-flex flex-row mb-3">
            <img class="mr-2" src="<?=$module->framework->getUrl('assets/images/entraid-logo.svg')?>" alt="EntraID Logo" class="img-fluid" style="width: 64px;">
            <h1 class="align-self-center">EntraID Users</h1>
    </div>
    <div class="mb-2">
        <p>Below is a list of all users in the system and their EntraID status.</p>
    </div>
    <div class="border border-secondary-subtle p-3 rounded-2">
        <div class="d-flex flex-row mb-3">
            <button id="entraButton" class="btn btn-info mr-2" onclick="convertToEntra()" disabled>Convert to Entra ID</button>
            <button id="tableButton" class="btn btn-warning" onclick="convertToTable()" disabled>Convert to Table</button>
            <select id="userTypeSelect" class="form-select ml-auto" style="width: 200px;">
                <option disabled selected value>Filter by User Type</option>
                <option value="all">All Users</option>
                <option value="entraid">EntraID Users</option>
                <option value="table">Table Users</option>
            </select>
        </div>
        <table id="users-table" class="hover stripe row-border" style="width:100%">
            <thead>
                <tr>
                    <th></th>
                    <th>Username</th>
                    <th>First Name</th>
                    <th>Last Name</th>
                    <th>Email</th>
                    <th>EntraID</th>
                </tr>
            </thead>
            <tbody>
            </tbody>
        </table>
    </div>
</div>
<script>
    const entraid = <?=$module->framework->getJavascriptModuleObjectName()?>;
    function updateButtons() {
        const table = $('#users-table').DataTable();
        const selectedRows = table.rows({ selected: true }).count();
        $('#entraButton').prop('disabled', selectedRows === 0);
        $('#tableButton').prop('disabled', selectedRows === 0);
    }
    function convertToEntra() {
        const table = $('#users-table').DataTable();
        const selectedRows = table.rows({ selected: true }).data();
        const usernames = selectedRows.map(row => row.username).toArray();
        Swal.fire({
            title: entraid.tt('convert_5'),
            input: 'select',
            inputOptions: entraid.authTypes,
            icon: "warning",
            showCancelButton: true,
            confirmButtonText:  entraid.tt('convert_6')
        }).then((result) => {
            if (result.isConfirmed) {
                let siteId = result.value;
                entraid.ajax('convertTableUsersToEntraIdUsers', {
                    usernames: usernames,
                    siteId: siteId
                }).then(() => {
                    location.reload();
                });
            }
        });
    }
    function convertToTable() {
        const table = $('#users-table').DataTable();
        const selectedRows = table.rows({ selected: true }).data();
        const usernames = selectedRows.map(row => row.username).toArray();
        Swal.fire({
            title: entraid.tt('convert_7'),
            icon: "warning",
            showCancelButton: true,
            confirmButtonText:  entraid.tt('convert_8')
        }).then((result) => {
            if (result.isConfirmed) {
                let siteId = result.value;
                entraid.ajax('convertEntraIdUsersToTableUsers', {
                    usernames: usernames
                }).then(() => {
                    location.reload();
                });
            }
        });
    }
    function filterUserType() {
        const table = $('#users-table').DataTable();
        const selectedUserType = $('#userTypeSelect').val();
        let searchTerm = selectedUserType;
        let searchOptions = {};
        if (selectedUserType === 'all') {
            searchTerm = '';
        } else if (selectedUserType === 'entraid') {
            searchTerm = (d) => d !== 'false';
        } else if (selectedUserType === 'table') {
            searchTerm = 'false';
            searchOptions = {exact: true};
        }
        table.column(5).search(searchTerm, searchOptions).draw();
    }
    $(function() {
        $('#users-table').DataTable({
            processing: true,
            select: {
                style: 'multi',
                selector: 'td:first-child'
            },
            ajax: function (data, callback, settings) {
                entraid.ajax('getEntraIdUsers')
                .then(function (data) {
                    console.log(JSON.parse(data));
                    callback(JSON.parse(data));
                })
                .catch(function (error) {
                    console.error(error);
                    callback({ data: [] });
                });
            },
            order: [1, 'asc'],
            columns: [
                { 
                    sortable: false,
                    render: DataTable.render.select()
                },
                { 
                    title: "Username",
                    data: function (row, type, set, meta) {
                        return `<a class="text-primary link-underline-primary" target="_blank" rel="noopener noreferrer" href="${app_path_webroot_full}${app_path_webroot}ControlCenter/view_users.php?username=${row.username}">${row.username}</a>`;
                    }
                },
                { data: "user_firstname" },
                { data: "user_lastname" },
                { 
                    title: "Email",
                    data: function (row, type, set, meta) {
                        return `<a class="text-danger-emphasis" href="mailto:${row.user_email}">${row.user_email}</a>`;
                    }
                },
                {
                    title: 'Entra ID User Type',
                    data: function (row, type, set, meta) {

                        if (type === 'filter') {
                            return row.siteId;
                        }

                        if (row.entraid === 'false' || row.entraid === null) {
                            return 'Table';
                        }

                        return `<strong>${row.label}</strong> (${row.authType})`;

                    }
                }
            ],
            initComplete: function () {
                const table = $('#users-table').DataTable();
                table.on('select deselect', function () {
                    updateButtons();
                });

                // Add all auth type options to user type select
                entraid.authTypesRaw = JSON.parse('<?= json_encode($siteInfo) ?>');

                entraid.authTypes = new Map();
                entraid.authTypesRaw.forEach((authType) => {
                    entraid.authTypes.set(authType['siteId'], `<strong>${authType['label']}</strong> (${authType['authType']})`);
                });
                entraid.authTypes.forEach((value, siteId) => {
                    $('#userTypeSelect').append(`<option value="${siteId}">${value}</option>`);
                });
                $('#userTypeSelect').on('change', function () {
                    filterUserType();
                });
            }
        });
    });
</script>