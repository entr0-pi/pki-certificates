(function () {
    function renderConsistencyResults(data) {
        var html = "";

        if (data.success) {
            html += '<div role="alert" class="alert alert-success mb-4">';
            html += '<svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
            html += '<div><h3 class="font-semibold">All consistency checks passed ✅</h3></div></div>';
        } else {
            html += '<div role="alert" class="alert alert-error mb-4">';
            html += '<svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l-2-2m0 0l-2-2m2 2l2-2m-2 2l-2 2m0 0l2 2m-2-2l-2 2"></path></svg>';
            html += "<div><h3 class=\"font-semibold\">Inconsistencies found</h3>";
            if (data.error) {
                html += "<p class=\"text-sm\">" + data.error + "</p>";
            }
            html += "</div></div>";
        }

        if (data.stats) {
            var stats = data.stats;
            var tests = [
                ["Certificate file exists", stats.missing_files],
                ["Subject fields match DB", stats.subject_mismatches],
                ["Issuer linkage consistency", stats.issuer_link_mismatches],
                ["Serial format validity", stats.serial_format_issues],
                ["Serial uniqueness (global)", stats.serial_duplicates_global],
                ["Serial uniqueness (per org)", stats.serial_duplicates_per_org],
                ["Validity dates match DB", stats.validity_mismatches],
                ["Validity ranges are valid", stats.invalid_validity_ranges],
                ["Type-policy consistency", stats.type_policy_mismatches],
                ["Artifact path integrity", stats.artifact_path_mismatches],
                ["Private key matches cert", stats.key_cert_mismatches],
                ["Private key loadability", stats.key_load_failures],
                ["CSR consistency", stats.csr_mismatches],
                ["CRL file presence", stats.crl_mismatches],
                ["CRL semantic consistency", stats.crl_semantic_mismatches],
                ["No orphaned records", stats.orphaned_records],
                ["Status-state consistency", stats.status_state_mismatches],
                ["Encryption/naming policy", stats.encryption_naming_mismatches],
                ["Hash integrity baseline", stats.hash_mismatches],
            ];

            html += '<div class="mb-4"><h4 class="font-semibold text-sm mb-2">Test Results</h4>';
            html += '<div class="space-y-2 text-sm">';

            tests.forEach(function (test) {
                var label = test[0];
                var failures = test[1];
                var fail = Number(failures || 0) > 0;
                var badgeClass = fail ? "badge-error" : "badge-success";
                var statusText = fail ? "FAIL (" + failures + ")" : "OK";
                var icon = fail
                    ? '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-error" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>'
                    : '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';

                html += '<div class="flex items-center justify-between bg-base-200 rounded-box p-2">';
                html += '<div class="flex items-center gap-2">' + icon + "<span>" + label + "</span></div>";
                html += '<span class="badge ' + badgeClass + ' badge-sm">' + statusText + "</span>";
                html += "</div>";
            });

            html += '<div class="mt-3 text-xs text-base-content/70">';
            html += "Checked certificates: " + (stats.checked_certs || 0) + " / " + (stats.total_certs || 0) + "<br>";
            html += "Hash tracked files: " + (stats.hash_tracked_files || 0) + ", new baseline entries: " + (stats.hash_new_entries || 0) + "<br>";
            if (stats.crl_certs_checked !== undefined) {
                html += "Certificates with CRLs checked: " + (stats.crl_certs_checked || 0);
            } else {
                html += "Warnings: " + (stats.warnings || 0);
            }
            html += "</div></div></div>";
        }

        if (data.issues && data.issues.length > 0) {
            html += '<div><h4 class="font-semibold text-sm mb-2">Issues Found (' + (data.issue_count || data.issues.length) + ")</h4>";
            html += '<div class="space-y-2 text-sm max-h-64 overflow-y-auto">';
            data.issues.forEach(function (issue) {
                var bgClass = issue.level === "error" ? "bg-error/10 border-error" : "bg-warning/10 border-warning";
                var badgeClass = issue.level === "error" ? "badge-error" : "badge-warning";
                html += '<div class="card ' + bgClass + ' border p-3">';
                html += '<div class="badge ' + badgeClass + ' badge-sm">' + String(issue.level || "").toUpperCase() + "</div>";
                html += '<p class="text-xs mt-2">' + issue.message + "</p>";
                html += "</div>";
            });
            html += "</div></div>";
        } else if (!data.success && data.error) {
            html += '<div class="text-sm text-base-content/70">No issues details available.</div>';
        } else {
            html += '<div class="text-sm text-success">No issues found. Database and PEM files are consistent.</div>';
        }

        return html;
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
