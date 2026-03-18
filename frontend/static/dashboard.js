// Read data island
const _d = JSON.parse(document.getElementById('dashboard-data').textContent);
const orgId                   = _d.orgId;
const EXPIRY_CRITICAL_DAYS    = _d.criticalDays;
const EXPIRY_WARNING_DAYS     = _d.warningDays;
const EXPIRY_ALERT_WINDOW_DAYS = _d.expirationDays;

// Toggle Recent Operations visibility
function toggleAuditLogs() {
    const content = document.getElementById("auditLogsContent");
    content.classList.toggle("hidden");
}

// CRL Distribution - fetch available CRLs
async function loadCrlList() {
    const loading = document.getElementById("crlLoading");
    const content = document.getElementById("crlContent");
    const error = document.getElementById("crlError");
    const issuersList = document.getElementById("crlIssuersList");

    try {
        const response = await fetch(`/api/organizations/${orgId}/crls`);
        const crls = await response.json();

        if (!Array.isArray(crls) || crls.length === 0) {
            loading.classList.add("hidden");
            error.classList.remove("hidden");
            return;
        }

        // Filter to issuers with CRLs
        const availableCrls = crls.filter(c => c.has_crl);
        if (availableCrls.length === 0) {
            loading.classList.add("hidden");
            error.classList.remove("hidden");
            return;
        }

        // Render issuers with landing-page style cards
        issuersList.innerHTML = availableCrls.map(crl => {
            const lastUpdated = crl.last_updated ? new Date(crl.last_updated).toLocaleString() : "Never";
            const bundleBtn = `<a href="/organizations/${orgId}/crl/bundle" class="btn btn-ghost btn-xs" title="Download CRL Bundle (All CRLs)" download>
                     <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                         <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.658 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                     </svg>
                   </a>`;
            return `
                <div class="card bg-base-200 shadow transition-shadow hover:shadow-lg duration-200">
                    <div class="card-body p-3 gap-2">
                        <div class="flex items-start justify-between gap-2">
                            <h3 class="font-semibold text-sm flex-1">${crl.issuer_name}</h3>
                            <div class="badge badge-outline badge-xs">${crl.cert_type}</div>
                        </div>
                        <div class="text-xs text-base-content/60">
                            Updated: ${lastUpdated}
                        </div>
                        <div class="text-xs">
                            ${crl.revoked_count > 0 ? `<span class="text-error font-semibold">${crl.revoked_count}</span> <span class="text-base-content/60">revoked</span>` : '<span class="text-base-content/50">No revocations</span>'}
                        </div>
                        <div class="flex items-center justify-between gap-2">
                            <div class="flex gap-1">
                                ${bundleBtn}
                                <a href="${crl.download_url}" class="btn btn-ghost btn-xs" title="Download CRL" download>
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                    </svg>
                                </a>
                            </div>
                            ${crl.issuer_status === 'revoked' ? '<div class="badge badge-error badge-sm">Revoked</div>' : ''}
                        </div>
                    </div>
                </div>
            `;
        }).join("");

        loading.classList.add("hidden");
        content.classList.remove("hidden");
    } catch (err) {
        console.error("Failed to load CRL list:", err);
        loading.classList.add("hidden");
        error.classList.remove("hidden");
    }
}

// Load CRL list on page load
document.addEventListener("DOMContentLoaded", loadCrlList);

const revokeModal = document.getElementById("revokeModal");
const revokeForm = document.getElementById("revokeForm");
function openRevokeModal(certId, certName, issuerType, certType) {
    if (certType === "root") {
        document.getElementById("rootRevokeBlockModal").showModal();
        return;
    }
    document.getElementById("certNameDisplay").value = certName;
    revokeForm.action = `/organizations/${orgId}/certificates/${certId}/revoke`;

    const rootField = document.getElementById("rootPasswordField");
    const rootInput = document.getElementById("rootPasswordInput");
    rootInput.value = "";
    if (issuerType === "root") {
        rootField.classList.remove("hidden");
        rootInput.required = true;
    } else {
        rootField.classList.add("hidden");
        rootInput.required = false;
    }
    revokeModal.showModal();
}

const rows = Array.from(document.querySelectorAll(".cert-row"));
const q = document.getElementById("certSearch");
const type = document.getElementById("typeFilter");
const status = document.getElementById("statusFilter");
const expiry = document.getElementById("expiryFilter");
const noResults = document.getElementById("noResultsMessage");

function expiryBucket(notAfter) {
    if (!notAfter) return "";
    const end = new Date(notAfter);
    if (Number.isNaN(end.getTime())) return "";
    const days = Math.ceil((end - new Date()) / 86400000);
    if (days <= 0) return "expired";
    if (days <= EXPIRY_CRITICAL_DAYS) return "critical";
    if (days <= EXPIRY_WARNING_DAYS) return "warning";
    if (days <= EXPIRY_ALERT_WINDOW_DAYS) return "info";
    return "healthy";
}

function renderExpiryBadges() {
    rows.forEach((row) => {
        const bucket = expiryBucket(row.dataset.notAfter || "");
        const badge = row.querySelector(".expiry-badge");
        if (!badge) return;
        if (!bucket) {
            badge.textContent = "-";
            badge.className = "expiry-badge badge badge-sm badge-ghost";
            return;
        }
        if (bucket === "expired") badge.className = "expiry-badge badge badge-sm badge-error";
        else if (bucket === "critical") badge.className = "expiry-badge badge badge-sm badge-error";
        else if (bucket === "warning") badge.className = "expiry-badge badge badge-sm badge-warning";
        else if (bucket === "info") badge.className = "expiry-badge badge badge-sm badge-info";
        else badge.className = "expiry-badge badge badge-sm badge-success";
        badge.textContent = bucket;
    });
}

function applyFilters() {
    const query = (q?.value || "").trim().toLowerCase();
    const t = type?.value || "";
    const s = status?.value || "";
    const e = expiry?.value || "";
    let visible = 0;
    rows.forEach((row) => {
        const haystack = [row.dataset.name, row.dataset.cn, row.dataset.serial, row.dataset.reason].join(" ");
        const matchesQuery = !query || haystack.includes(query);
        const matchesType = !t || row.dataset.type === t;
        const matchesStatus = !s || row.dataset.status === s;
        const matchesExpiry = !e || expiryBucket(row.dataset.notAfter || "") === e;
        const show = matchesQuery && matchesType && matchesStatus && matchesExpiry;
        row.classList.toggle("hidden", !show);
        if (show) visible += 1;
    });
    if (noResults) noResults.classList.toggle("hidden", visible !== 0);
}

// Event delegation for loop-rendered rows
document.querySelector('#certTableBody')?.addEventListener('click', (e) => {
    // Popup links
    const popupLink = e.target.closest('a[href*="popup"]');
    if (popupLink) {
        e.preventDefault();
        const id = popupLink.href.match(/\/(\d+)\/popup/)?.[1];
        if (id) {
            window.open(popupLink.href, 'certPopup' + id, 'width=1200,height=900,scrollbars=yes,resizable=yes');
        }
        return;
    }
    // PKCS12 button (has org-id and cert-id)
    const p12Btn = e.target.closest('[data-org-id][data-cert-id]:not([data-cert-name])');
    if (p12Btn) {
        e.preventDefault();
        showP12Password(p12Btn.dataset.orgId, p12Btn.dataset.certId);
        return;
    }
    // Revoke button (has cert-id and cert-name)
    const revokeBtn = e.target.closest('[data-cert-id][data-cert-name]');
    if (revokeBtn) {
        e.preventDefault();
        const row = revokeBtn.closest('tr');
        openRevokeModal(revokeBtn.dataset.certId, revokeBtn.dataset.certName,
            row.dataset.issuerType, row.dataset.type);
        return;
    }
});

// Bind modal buttons by ID
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('toggleAuditBtn')?.addEventListener('click', toggleAuditLogs);
    document.getElementById('consistencyCheckBtn')?.addEventListener('click', runConsistencyCheck);

    const p12CopyBtn = document.querySelector('#p12PasswordModal .btn-ghost');
    if (p12CopyBtn) {
        p12CopyBtn.addEventListener('click', copyP12Password);
    }

    const p12CloseBtn = document.querySelector('#p12PasswordModal button.btn-ghost:first-child');
    if (p12CloseBtn) {
        p12CloseBtn.addEventListener('click', () => p12PasswordModal.close());
    }

    const revokeCloseBtn = document.querySelector('#revokeModal button.btn-ghost');
    if (revokeCloseBtn) {
        revokeCloseBtn.addEventListener('click', () => revokeModal.close());
    }

    const rootRevokeCloseBtn = document.querySelector('#rootRevokeBlockModal button');
    if (rootRevokeCloseBtn) {
        rootRevokeCloseBtn.addEventListener('click', () => rootRevokeBlockModal.close());
    }

    document.getElementById('consistencyCheckCloseBtn')?.addEventListener('click', () => consistencyModal.close());
});

[q, type, status, expiry].forEach((el) => el && el.addEventListener("input", applyFilters));
renderExpiryBadges();
applyFilters();
