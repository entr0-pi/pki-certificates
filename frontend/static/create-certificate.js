// Read data island
const _d = JSON.parse(document.getElementById('cert-form-data').textContent);
const endEntityPolicies        = _d.endEntityPolicies;
const issuerFieldsIntermediate = _d.issuerSubjectFields;
const lockedIntermediate       = _d.lockedFieldsIntermediate;
const lockedEndEntity          = _d.lockedFieldsEndEntity;
const issuerSubjectMap         = JSON.parse(_d.issuerSubjectMapJson);

const tabs = Array.from(document.querySelectorAll("[data-mode]"));
const panels = {
    root: document.getElementById("panel-root"),
    intermediate: document.getElementById("panel-intermediate"),
    "end-entity": document.getElementById("panel-end-entity")
};
let currentMode = "root";
function setMode(mode) {
    currentMode = mode;
    tabs.forEach(t => t.classList.toggle("tab-active", t.dataset.mode === mode));
    Object.entries(panels).forEach(([k, el]) => el.classList.toggle("hidden", k !== mode));
}
tabs.forEach(t => t.addEventListener("click", () => setMode(t.dataset.mode)));

function applyLocked(fieldId, source, key, lockedKeys) {
    const el = document.getElementById(fieldId);
    if (!el) return;
    const locked = lockedKeys.includes(key);
    if (locked) {
        el.value = source[key] || "";
        el.readOnly = true;
        el.classList.add("input-disabled");
    } else {
        el.readOnly = false;
        el.classList.remove("input-disabled");
    }
}

function syncRequiredMarkers(root = document) {
    const controls = root.querySelectorAll(".form-control");
    controls.forEach((control) => {
        const labelText = control.querySelector(".label .label-text");
        if (!labelText) return;
        const field = control.querySelector("input:not([type='hidden']), select, textarea");
        if (!field) return;
        const marker = labelText.querySelector(".required-marker");
        const forcedRequired = control.dataset.forceRequiredMarker === "true";
        const required = field.required || forcedRequired;

        if (required && !marker) {
            const star = document.createElement("span");
            star.className = "required-marker";
            star.textContent = "*";
            labelText.appendChild(star);
        } else if (!required && marker) {
            marker.remove();
        }
    });
}

["C","ST","L","O","OU","email"].forEach((k) => applyLocked("int_" + k.toLowerCase(), issuerFieldsIntermediate, k, lockedIntermediate));

function applyEndEntityLocks() {
    const issuer = document.getElementById("issuerName");
    if (!issuer) return;
    const values = issuerSubjectMap[issuer.value] || {};
    ["C","ST","L","O","OU","email"].forEach((k) => applyLocked("ee_" + k.toLowerCase(), values, k, lockedEndEntity));
}

const eeType = document.getElementById("eeType");
const eeButtons = Array.from(document.querySelectorAll("[data-ee-type]"));
const ocspToggle = document.getElementById("ocspToggle");
const ocspToggleContainer = document.getElementById("ocspToggleContainer");

// OCSP toggle handler: flips between "server" and "ocsp" cert_type, and hides SAN when checked
if (ocspToggle) {
    ocspToggle.addEventListener("change", function () {
        if (eeType.value === "server" || eeType.value === "ocsp") {
            eeType.value = this.checked ? "ocsp" : "server";
        }
        // Update badge
        const badge = document.getElementById("certTypeBadge");
        if (badge) {
            badge.textContent = this.checked ? "ocsp" : "normal server";
            badge.className = this.checked ? "badge badge-outline badge-secondary" : "badge badge-outline";
        }
        // Highlight container border when OCSP is active
        if (ocspToggleContainer) {
            ocspToggleContainer.classList.toggle("border-accent", this.checked);
            ocspToggleContainer.classList.toggle("border-transparent", !this.checked);
        }
        // Update default days based on cert type and recalculate enddate
        const daysInput = document.querySelector('#days-input-end-entity input[data-type="days"]');
        if (daysInput && endEntityPolicies) {
            const certType = this.checked ? "ocsp" : "server";
            daysInput.value = endEntityPolicies[certType].days;
            // Trigger input event to recalculate enddate
            daysInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
        // Hide SAN section when OCSP is enabled
        const sanSection = document.getElementById("sanSection");
        const sanHidden = document.getElementById("sanHidden");
        if (this.checked) {
            sanSection.classList.add("hidden");
            // Clear SAN data when OCSP is enabled
            document.getElementById("sanRows").innerHTML = "";
            if (sanHidden) sanHidden.value = "";
        } else {
            sanSection.classList.remove("hidden");
            // Restore a default SAN row when OCSP is disabled
            if (!document.getElementById("sanRows").children.length) addSanRow();
        }
    });
}

function setEndEntityType(type) {
    if (!eeType) return;
    eeType.value = type;

    // Update default days and EC curve from policy
    if (endEntityPolicies[type]) {
        const daysInput = document.querySelector('#days-input-end-entity input[data-type="days"]');
        const eccurveSelect = document.querySelector('#panel-end-entity select[name="eccurve"]');
        if (daysInput) {
            daysInput.value = endEntityPolicies[type].days;
            daysInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
        if (eccurveSelect) {
            // Update the default option text to show the correct curve
            const defaultOption = eccurveSelect.querySelector('option[value=""]');
            if (defaultOption) {
                defaultOption.textContent = `Default curve (${endEntityPolicies[type].curve})`;
            }
            eccurveSelect.value = "";
        }
    }

    // Show OCSP toggle only for server type
    if (ocspToggleContainer) {
        if (type === "server") {
            ocspToggleContainer.classList.remove("hidden");
            ocspToggleContainer.classList.add("flex");
        } else {
            ocspToggleContainer.classList.add("hidden");
            ocspToggleContainer.classList.remove("flex");
            // Reset OCSP toggle when switching away from server
            if (ocspToggle) {
                ocspToggle.checked = false;
            }
        }
    }

    eeButtons.forEach((b) => {
        const active = b.dataset.eeType === type;
        b.classList.toggle("btn-primary", active);
        b.classList.toggle("btn-outline", !active);
    });
    const sanSection = document.getElementById("sanSection");
    const eeEmail = document.getElementById("eeEmail");
    if (type === "server") {
        sanSection.classList.remove("hidden");
        eeEmail.required = false;
        if (!document.getElementById("sanRows").children.length) addSanRow();
    } else if (type === "email") {
        sanSection.classList.add("hidden");
        eeEmail.required = true;
        document.getElementById("sanRows").innerHTML = "";
        document.getElementById("sanHidden").value = "";
    } else {
        sanSection.classList.add("hidden");
        eeEmail.required = false;
        document.getElementById("sanRows").innerHTML = "";
        document.getElementById("sanHidden").value = "";
    }
    syncRequiredMarkers(document.getElementById("panel-end-entity"));
}
eeButtons.forEach((b) => b.addEventListener("click", () => setEndEntityType(b.dataset.eeType)));

function validateSanValue(type, value) {
    if (!value || !value.trim()) return true; // Empty is OK (user can delete)
    const v = value.trim();

    if (type === "DNS") {
        // Allow simple names, FQDN, and wildcards
        // Pattern: (*.)?label(.label)*
        const dnsPattern = /^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/;
        return dnsPattern.test(v);
    } else if (type === "IP") {
        // Try to parse as IPv4 or IPv6 using regex
        const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6 = /^([\da-fA-F]{0,4}:){2,7}[\da-fA-F]{0,4}$/;
        if (ipv4.test(v)) {
            const parts = v.split(".").map(p => parseInt(p));
            return parts.every(p => p >= 0 && p <= 255);
        }
        return ipv6.test(v);
    } else if (type === "EMAIL") {
        // Basic email: user@domain.tld
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailPattern.test(v);
    } else if (type === "URI") {
        // Must start with a valid scheme
        const uriPattern = /^(https?|ldap|ldaps|ftp|ftps):\/\/.+/i;
        return uriPattern.test(v);
    }
    return false;
}

function addSanRow(type = "DNS", value = "") {
    const row = document.createElement("div");
    row.className = "flex gap-2";
    row.innerHTML = `<select class="select select-bordered select-sm w-24"><option>DNS</option><option>IP</option><option>URI</option><option>EMAIL</option></select><input class="input input-bordered input-sm flex-1" value="${value}" placeholder="value"><button type="button" class="btn btn-sm btn-ghost text-error">x</button>`;
    const btn = row.querySelector("button");
    const sel = row.querySelector("select");
    const inp = row.querySelector("input");
    sel.value = type;
    btn.addEventListener("click", () => { row.remove(); buildSan(); });
    inp.addEventListener("input", () => {
        const currentType = sel.value;
        const isValid = validateSanValue(currentType, inp.value);
        inp.classList.toggle("input-error", !isValid && inp.value.trim());
        inp.classList.toggle("input-success", isValid && inp.value.trim());
        buildSan();
    });
    sel.addEventListener("change", () => {
        const currentType = sel.value;
        const isValid = validateSanValue(currentType, inp.value);
        inp.classList.toggle("input-error", !isValid && inp.value.trim());
        inp.classList.toggle("input-success", isValid && inp.value.trim());
        buildSan();
    });
    document.getElementById("sanRows").appendChild(row);
    buildSan();
}

function buildSan() {
    const rows = Array.from(document.querySelectorAll("#sanRows > div"));
    const parts = rows.map((row) => {
        const t = row.querySelector("select").value;
        const v = row.querySelector("input").value.trim();
        return v ? `${t}:${v}` : "";
    }).filter(Boolean);
    const hidden = document.getElementById("sanHidden");
    if (hidden) hidden.value = parts.join(", ");
}

document.getElementById("issuerName")?.addEventListener("change", function() {
    applyEndEntityLocks();

    // Pre-fill OU with Organization_issuerName format
    const issuerName = this.value;
    const issuerData = issuerSubjectMap[issuerName] || {};
    const organization = issuerData["O"] || "";
    const ouField = document.getElementById("ee_ou");

    if (ouField && organization && issuerName) {
        ouField.value = `${organization}_${issuerName}`;
    }
});

function validateAllSans() {
    const rows = Array.from(document.querySelectorAll("#sanRows > div"));
    for (const row of rows) {
        const sel = row.querySelector("select");
        const inp = row.querySelector("input");
        const type = sel.value;
        const value = inp.value.trim();
        if (value && !validateSanValue(type, value)) {
            inp.classList.add("input-error");
            inp.focus();
            return false;
        }
    }
    return true;
}

const endEntityForm = document.getElementById("endEntityForm");
if (endEntityForm) {
    endEntityForm.addEventListener("submit", (e) => {
        if (!validateAllSans()) {
            e.preventDefault();
            // Show error alert (form already has error styling via input-error class)
            const alert = document.createElement("div");
            alert.className = "alert alert-error mb-4";
            alert.innerHTML = '<span>Please fix SAN entries (marked in red) before submitting.</span>';
            endEntityForm.insertAdjacentElement("beforebegin", alert);
            setTimeout(() => alert.remove(), 5000);
        }
    });
}


setMode("root");
setEndEntityType("server");
applyEndEntityLocks();
syncRequiredMarkers();

const requiredObserver = new MutationObserver((mutations) => {
    if (mutations.some((m) => m.type === "attributes" && m.attributeName === "required")) {
        syncRequiredMarkers();
    }
});
document.querySelectorAll("input, select, textarea").forEach((field) => {
    requiredObserver.observe(field, { attributes: true, attributeFilter: ["required"] });
});

// Duration picker handler
function setupDurationToggle(form) {
    const radios = form.querySelectorAll('input[name="duration_type"]');
    const daysInputDiv = form.querySelector('[id^="days-input-"]');
    const dateInputDiv = form.querySelector('[id^="date-input-"]');
    const endDateHidden = form.querySelector('input[name="enddate"]');

    if (!radios.length) return;

    function updateEndDate() {
        const checkedRadio = form.querySelector('input[name="duration_type"]:checked');
        if (checkedRadio.value === "days") {
            const daysInput = daysInputDiv.querySelector('input');
            const days = parseInt(daysInput.value || "365");
            const date = new Date();
            date.setDate(date.getDate() + days);
            endDateHidden.value = date.toISOString().replace(/[-:TZ.]/g, '').slice(0, 14) + 'Z';
        } else {
            const dateInput = dateInputDiv.querySelector('input');
            if (dateInput.value) {
                const date = new Date(dateInput.value + 'T00:00:00Z');
                endDateHidden.value = date.toISOString().replace(/[-:TZ.]/g, '').slice(0, 14) + 'Z';
            }
        }
    }

    radios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === "days") {
                daysInputDiv.classList.remove('hidden');
                dateInputDiv.classList.add('hidden');
            } else {
                daysInputDiv.classList.add('hidden');
                dateInputDiv.classList.remove('hidden');
            }
            updateEndDate();
        });
    });

    daysInputDiv.querySelector('input')?.addEventListener('input', updateEndDate);
    dateInputDiv.querySelector('input')?.addEventListener('change', updateEndDate);

    updateEndDate();
}

// Setup duration pickers for all forms
document.querySelectorAll('.cert-form').forEach(form => {
    setupDurationToggle(form);
});

// Bind the "Add SAN" button
document.getElementById('addSanBtn')?.addEventListener('click', () => addSanRow());
