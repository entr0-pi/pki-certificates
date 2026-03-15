(function () {
    function renderConsistencyResults(data) {
        var html = "";

        // Status banner
        if (data.success) {
            html += '<div role="alert" class="alert alert-success mb-4">';
            html += '<svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
            html += '<div><h3 class="font-semibold">All checks passed ✅</h3></div></div>';
        } else {
            html += '<div role="alert" class="alert alert-error mb-4">';
            html += '<svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4v2m0 4v2M7.08 6.06A9 9 0 1020.94 19.92M7.08 6.06l5.78 5.78m0 0l5.78-5.78"/></svg>';
            html += "<div><h3 class=\"font-semibold\">Issues found</h3></div></div>";
        }

        // Issues section (most important)
        if (data.issues && data.issues.length > 0) {
            var errorCount = data.issues.filter(i => i.level === "error").length;
            var warningCount = data.issues.filter(i => i.level === "warning").length;
            html += '<div class="mb-6">';
            html += '<h3 class="font-semibold text-base mb-3">🔍 Issues Found</h3>';

            // Separate errors and warnings
            if (errorCount > 0) {
                html += '<div class="mb-4"><p class="text-xs font-semibold text-error mb-2">ERRORS (' + errorCount + ')</p>';
                html += '<div class="space-y-2">';
                data.issues.filter(i => i.level === "error").forEach(function (issue) {
                    html += '<div class="bg-error/10 border-l-2 border-error rounded p-3 text-sm">';
                    html += '<p class="font-mono text-xs">' + escapeHtml(issue.message) + '</p>';
                    html += '</div>';
                });
                html += '</div></div>';
            }

            if (warningCount > 0) {
                html += '<div><p class="text-xs font-semibold text-warning mb-2">WARNINGS (' + warningCount + ')</p>';
                html += '<div class="space-y-2">';
                data.issues.filter(i => i.level === "warning").forEach(function (issue) {
                    html += '<div class="bg-warning/10 border-l-2 border-warning rounded p-3 text-sm">';
                    html += '<p class="font-mono text-xs">' + escapeHtml(issue.message) + '</p>';
                    html += '</div>';
                });
                html += '</div></div>';
            }

            html += '</div>';
        }

        // Summary stats
        if (data.stats) {
            var stats = data.stats;
            html += '<div class="mb-6">';
            html += '<h3 class="font-semibold text-base mb-3">📊 Summary</h3>';
            html += '<div class="grid grid-cols-2 gap-3 text-sm">';
            html += '<div class="bg-base-200 rounded p-3"><p class="text-xs opacity-70">Certificates</p><p class="text-lg font-semibold">' + (stats.checked_certs || 0) + ' / ' + (stats.total_certs || 0) + '</p></div>';
            html += '<div class="bg-base-200 rounded p-3"><p class="text-xs opacity-70">Files Tracked</p><p class="text-lg font-semibold">' + (stats.hash_tracked_files || 0) + '</p></div>';
            html += '</div>';
            html += '</div>';
        }

        return html;
    }

    function escapeHtml(text) {
        var map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return String(text || '').replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    window.runConsistencyCheck = async function runConsistencyCheck() {
        var modal = document.getElementById("consistencyModal") || document.getElementById("consistencyCheckModal");
        var body = document.getElementById("consistencyBody") || document.getElementById("consistencyContent");
        if (!modal || !body) {
            return;
        }

        modal.showModal();
        body.innerHTML = '<div class="flex justify-center items-center py-8"><span class="loading loading-spinner loading-lg"></span></div>';

        try {
            var response = await fetch("/api/check-consistency");
            var data = await response.json();
            body.innerHTML = renderConsistencyResults(data);
        } catch (error) {
            body.innerHTML = '<div role="alert" class="alert alert-error"><span>Error running consistency check.</span></div>';
        }
    };
})();
