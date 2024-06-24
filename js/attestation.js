document.addEventListener("DOMContentLoaded", function () {
    const module = __MODULE__;
    document.getElementById('attestation-submit-button').addEventListener('click', function () {
        if (document.getElementById('attestation-checkbox').checked) {
            module.ajax('handleAttestation', {
                username: '{{USERNAME}}',
                siteId: '{{SITE_ID}}',
                logId: '{{LOG_ID}}'
            }).then(result => {
                if (result === true) {
                    window.location.href = decodeURIComponent("{{ORIGIN_URL}}");
                } else {
                    console.log(result);
                }
            });
        }
    });
    document.getElementById('attestation-checkbox').addEventListener('change', function () {
        document.getElementById('attestation-submit-button').disabled = !this.checked;
    });
});