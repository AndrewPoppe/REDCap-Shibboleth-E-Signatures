<?php

namespace YaleREDCap\EntraIdAuthenticator;

/** @var EntraIdAuthenticator $module */

$module->framework->initializeJavascriptModuleObject();

?>
<link href="https://cdn.datatables.net/v/dt/jszip-3.10.1/dt-2.0.8/b-3.0.2/b-html5-3.0.2/sl-2.0.3/datatables.min.css" rel="stylesheet">
<script src="https://cdn.datatables.net/v/dt/jszip-3.10.1/dt-2.0.8/b-3.0.2/b-html5-3.0.2/sl-2.0.3/datatables.min.js"></script>
<table id="users-table" class="display">
    <thead>
        <tr>
            <!-- <th>
                <input type="checkbox" id="entraid_user_select_all" onchange="selectAllUsers(event)">
            </th> -->
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
<script>
    function selectAllUsers(event) {
        const checked = event.target.checked;
        const table = $('#users-table').DataTable();
        table.rows().select(checked);
        table.rows().nodes().each((row) => {
            row.querySelector('.entraid_user_select').checked = checked;
        });
    }
    function selectRow(event) {
        const checked = event.target.checked;
        const table = $('#users-table').DataTable();
        table.row(event.target.closest('tr')).select(checked);
    }
    $(function() {
        const entraid = <?=$module->framework->getJavascriptModuleObjectName()?>;
        $('#users-table').DataTable({
            processing: true,
            select: 'multi',
            // dom: 'Bfrtip',
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
                // { 
                //     data: function (row, type, set, meta) {
                //         return `<input type="checkbox" class="entraid_user_select" name="entraid_user_select" value="${row.username}" onchange="selectRow(event)">`;
                //     }
                // },
                { 
                    sortable: false,
                    render: DataTable.render.select()
                },
                { data: "username" },
                { data: "user_firstname" },
                { data: "user_lastname" },
                { data: "user_email" },
                {
                    title: 'Entra ID User Type',
                    data: function (row, type, set, meta) {
                        const auth_type = row.entraid === 'false' ? 'Table' : row.entraid;
                        return auth_type ?? 'Table';
                    }
                }
            ]
        });
    });
</script>