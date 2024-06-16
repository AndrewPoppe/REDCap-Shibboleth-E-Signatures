<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

$module->framework->initializeJavascriptModuleObject();
$module->framework->tt_transferToJavascriptModuleObject();
$settings = new EntraIdSettings($module);
$siteInfo = $settings->getSiteInfo();

?>
<link rel="stylesheet" href="https://cdn.datatables.net/v/bs5/jszip-3.10.1/dt-2.0.8/b-3.0.2/b-html5-3.0.2/r-3.0.2/sl-2.0.3/datatables.min.css" integrity="sha384-BcFALZmZqajgruYOHgCJFXQrZiknIJ+5UTpaRmRX6DGJwquZv9Rz/GbGJxg8Mu61" crossorigin="anonymous">
<script src="https://cdn.datatables.net/v/bs5/jszip-3.10.1/dt-2.0.8/b-3.0.2/b-html5-3.0.2/r-3.0.2/sl-2.0.3/datatables.min.js" integrity="sha384-HqqVqMvdcfldcjRlY1GXixx0JH1KO5ZIjILCfx6oWel0uff8b+NkPJ9ZQZUXqbcM" crossorigin="anonymous"></script>
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
a.attestation-link {
    cursor: pointer;
}
.pagination .page-link {
    font-size: inherit;
}
</style>
<div class="">
    <div class="d-flex flex-row mb-3">
            <img class="mr-2" src="<?=$module->framework->getUrl('assets/images/entraid-logo.svg')?>" alt="EntraID Logo" class="img-fluid" style="width: 64px;">
            <h1 class="align-self-center"><?= $module->framework->tt('entraid_users') ?></h1>
    </div>
    <div class="mb-2">
        <p><?= $module->framework->tt('dashboard_1') ?></p>
    </div>
    <div class="border border-secondary-subtle p-3 rounded-2">
        <div>
            <div id="selectContainer" class="d-flex flex-row ml-xl-auto mt-2 mt-xl-0">
                <select id="userTypeSelect" class="form-select" style="width: 200px;">
                    <option disabled selected value>User Type</option>
                    <option value="all">All Users</option>
                    <option value="entraid">EntraID Users</option>
                    <option value="table">Table Users</option>
                </select>
                <select id="attestationStatusSelect" class="form-select ml-2" style="width: 200px;">
                    <option disabled selected value>Attestation Status</option>
                    <option value="all">All Users</option>
                    <option value="current">Up-to-date Attestations</option>
                    <option value="out-of-date">Out-of-date Attestations</option>
                    <option value="none">No Attestation</option>
                    <option value="invalid">Out-of-date or No Attestation</option>
                </select>
            </div>
        </div>
        <table id="users-table" class="table table-striped hover w-100" style="">
            <thead>
                <tr>
                    <th></th>
                    <th>Username</th>
                    <th>First Name</th>
                    <th>Last Name</th>
                    <th>Email</th>
                    <th>EntraID</th>
                    <th>Attestation</th>
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
                }).then((result) => {
                    if (result === false) {
                        Swal.fire({
                            title: entraid.tt('convert_10'),
                            icon: "error"
                        });
                        return;
                    }
                    if (usernames.length > 1) {
                        Swal.fire({
                            title: entraid.tt('convert_9'),
                            icon: "success",
                            showConfirmButton: false
                        })
                        .then(() => {
                            location.reload();
                        });
                    } else {
                        location.reload();
                    }
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
            searchTerm = (d) => d !== '' && d !== 'false';
        } else if (selectedUserType === 'table') {
            searchTerm = (d) => d === '' || d === 'false';
        }
        table.column(5).search(searchTerm, searchOptions).draw();
    }
    function filterAttestationStatus() {
        const table = $('#users-table').DataTable();
        const selectedStatus = $('#attestationStatusSelect').val();
        let searchTerm = selectedStatus;
        let searchOptions = {};
        if (selectedStatus === 'all') {
            searchTerm = '';
        } else if (selectedStatus === 'current') {
            searchTerm = 'true';
        } else if (selectedStatus === 'out-of-date') {
            searchTerm = 'false';
        } else if (selectedStatus === 'none') {
            searchTerm = (d) => d === '';
        } else if (selectedStatus === 'invalid') {
            searchTerm = (d) => d === 'false' || d === '';
        }
        table.column(6).search(searchTerm, searchOptions).draw();
    }
    function getAttestationInfo(username) {
        const table = $('#users-table').DataTable();
        const row = table.row(`#${username}`).data();
        Swal.fire({
            title: 'Attestation',
            html: `
                <p><strong>${row.user_firstname} ${row.user_lastname}</strong> (${row.username})</p>
                <p>${formatAttestationData(row.attestationSiteLabel, row.attestationVersion, row.attestationDate)}</p>
                <div class="d-flex flex-column align-items-center">
                <p>${row.attestationText}</p>
                <p><input type="checkbox" id="cb" checked disabled><label class="ms-1" for="cb">${row.attestationCheckboxText}</label></p>
                </div>
            `,
            width: '50%',
            showConfirmButton: false
        });
    }
    function formatAttestationData(label, version, date) {
        return `<strong>${label}</strong> - version ${version}<br>${new Date(date).toDateString()}`;
    }
    function createAttestationLink(row) {
        try {
            return `<a class="attestation-link ${row.attestationCurrent ? 'text-success' : 'text-danger'}" onclick="getAttestationInfo('${row.username}')"><i class="fa-solid ${row.attestationCurrent ? 'fa-check' : 'fa-x'}"></i></a>`;
        } catch (error) {
            return '';
        }
    }
    $(function() {
        var table = $('#users-table').DataTable({
            processing: true,
            scrollX: true,
            select: {
                style: 'multi',
                selector: 'td:first-child'
            },
            ajax: function (data, callback, settings) {
                entraid.ajax('getEntraIdUsers')
                .then(function (data) {
                    callback({data : data});
                })
                .catch(function (error) {
                    console.error(error);
                    callback({ data: [] });
                });
            },
            layout: {
                top: [
                    {buttons: [{
                        extend: 'excelHtml5',
                        text: '<i class="fa-solid fa-file-excel"></i> Export',
                        className: 'btn btn-success me-2 nowrap',
                        exportOptions: {
                            format: {
                                body: function (html, row, column, node) {
                                    if (column === 6) {
                                        const data = table.row(row).data();
                                        const attestationData = {
                                            label: data.attestationSiteLabel,
                                            version: data.attestationVersion,
                                            date: data.attestationDate,
                                            current: data.attestationCurrent
                                        };
                                        return JSON.stringify(attestationData);
                                    }
                                    return DataTable.util.stripHtml(html);
                                }
                            },
                            customizeData: function (data) {
                                data.headerStructure[0].push({
                                    colspan: 1,
                                    rowspan: 1,
                                    title: 'Attestation Version'
                                },
                                {
                                    colspan: 1,
                                    rowspan: 1,
                                    title: 'Attestation Date'
                                },
                                {
                                    colspan: 1,
                                    rowspan: 1,
                                    title: 'Attestation Current'
                                });
                                data.headerStructure[0].shift();
                                data.body = data.body.map(row => {
                                    const attestationData = JSON.parse(row[6]);
                                    row[6] = attestationData.label;
                                    row[7] = attestationData.version;
                                    row[8] = attestationData.date;
                                    row[9] = attestationData.current ? 'Yes' : 'No';
                                    row.shift();
                                    return row;
                                });
                            }
                        },
                        filename: 'EntraID_Users_' + new Date().toISOString().slice(0, 10),
                        title: null
                    },{
                        // <button id="entraButton" class="btn btn-info mr-2 nowrap" onclick="convertToEntra()" disabled title="Convert table users to Entra ID users"><div class="d-flex flex-row justify-content-evenly align-items-center"><img src="<?=$module->framework->getUrl('assets/images/entraid-logo.svg')?>">&nbsp;<span>Convert</span></div></button>
            
                        text: '<div class="d-flex flex-row justify-content-evenly align-items-center"><img src="<?=$module->framework->getUrl('assets/images/entraid-logo.svg')?>">&nbsp;<span>Convert</span></div>',
                        className: 'btn btn-info mr-2 nowrap',
                        action: convertToEntra,
                        init: function (api, node, config) {
                            $(node).attr('title', 'Convert table users to Entra ID users');
                            $(node).attr('id', 'entraButton');
                            $(node).attr('disabled', true);
                        }            
                    },{
                        text: '<i class="fa-solid fa-table-list"></i>&nbsp;Convert',
                        className: 'btn btn-warning nowrap',
                        action: convertToTable,
                        init: function (api, node, config) {
                            $(node).attr('title', 'Convert Entra ID users to table users');
                            $(node).attr('id', 'tableButton');
                            $(node).attr('disabled', true);
                        }            
                    }]},
                    document.getElementById('selectContainer')                
                ],
            },
            rowId: 'username',
            order: [1, 'asc'],
            columnDefs: [
                {className: "dt-center", targets: 6}
            ],
            columns: [
                { 
                    sortable: false,
                    render: DataTable.render.select(),
                    responsivePriority: 1
                },
                { 
                    title: "Username",
                    data: function (row, type, set, meta) {
                        if (type !== 'display') {
                            return row.username;
                        }
                        return `<a class="text-primary link-underline-primary" target="_blank" rel="noopener noreferrer" href="${app_path_webroot_full}redcap_v${redcap_version}/ControlCenter/view_users.php?username=${row.username}">${row.username}</a>`;
                    },
                    responsivePriority: 1
                },
                { data: "user_firstname", responsivePriority: 2 },
                { data: "user_lastname", responsivePriority: 3 },
                { 
                    title: "Email",
                    data: function (row, type, set, meta) {
                        if (type !== 'display') {
                            return row.user_email;
                        }
                        return `<a class="text-danger-emphasis" href="mailto:${row.user_email}">${row.user_email}</a>`;
                    },
                    responsivePriority: 3
                },
                {
                    title: 'Entra ID User Type',
                    data: function (row, type, set, meta) {
                        if (type === 'sort') {
                            return row.label;
                        }

                        if (type === 'filter') {
                            return row.entraid;
                        }

                        if (row.entraid === 'false' || row.entraid === null) {
                            return 'Table';
                        }
                        if (type === 'display') {
                            if (row.passwordResetNeeded) {
                                return `<span class="text-danger">${entraid.tt('convert_11')}</span>`;
                            }
                            return `<strong>${row.label}</strong> (${row.authType})`;
                        }

                        return row.authType;
                    },
                    responsivePriority: 1
                },
                {
                    title: 'Attestation',
                    type: 'string',
                    data: function (row, type, set, meta) {
                        if (row.attestationText === null) {
                            return null;
                        }
                        if (type === 'filter') {
                            return row.attestationCurrent;
                        }

                        return createAttestationLink(row);
                    },
                    responsivePriority: 2
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
                $('#attestationStatusSelect').on('change', function () {
                    filterAttestationStatus();
                });
            }
        });
        $('.dt-buttons').removeClass('btn-group flex-wrap').addClass('nowrap');
        $('.dt-buttons').parent().addClass('d-flex flex-xl-row flex-column align-items-center justify-content-start');
        $('.dt-buttons').parent().parent().removeClass('mt-2');
        table.on('draw', function () {
            $('.dt-buttons').parent().addClass('d-flex flex-xl-row flex-column align-items-center justify-content-start');
        });
    });
</script>