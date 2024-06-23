$(document).ready(function () {
    const link = document.querySelector('#nav-tab-logout a');
    if (link) {
        link.href = '{{logout_url}}';
    }

    const projectLink = document.querySelector('#username-reference ~ span a');
    if (projectLink) {
        projectLink.href = '{{logout_url}}';
    }
});