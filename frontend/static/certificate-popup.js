function parseUtcTimestamp(raw) {
    if (!raw) {
        return null;
    }

    var normalized = String(raw).trim().replace(" ", "T");
    var match = normalized.match(
        /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$/
    );
    if (match) {
        return new Date(Date.UTC(
            Number(match[1]),
            Number(match[2]) - 1,
            Number(match[3]),
            Number(match[4]),
            Number(match[5]),
            Number(match[6])
        ));
    }

    var parsed = new Date(normalized);
    if (Number.isNaN(parsed.getTime())) {
        return null;
    }
    return parsed;
}

function showCopyToast(message) {
    var toast = document.getElementById("copy-toast-serial");
    if (!toast) {
        return;
    }
    toast.textContent = message;
    toast.style.display = "inline";
    setTimeout(function () {
        toast.style.display = "none";
        toast.textContent = "Copied!";
    }, 2000);
}

function copySerial(serial) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
        showCopyToast("Clipboard unavailable");
        return;
    }

    navigator.clipboard.writeText(serial).then(function () {
        showCopyToast("Copied!");
    }).catch(function () {
        showCopyToast("Copy failed");
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Validity bar
    var bar = document.getElementById("validity-bar");
    var lbl = document.getElementById("validity-label");
    if (bar && lbl) {
        var notBefore = bar.getAttribute("data-not-before");
        var notAfter = bar.getAttribute("data-not-after");
        if (notBefore && notAfter) {
            var start = parseUtcTimestamp(notBefore);
            var end = parseUtcTimestamp(notAfter);
            if (start && end && end > start) {
                var now = new Date();
                var total = end - start;
                var used = now - start;
                var pct = Math.max(0, Math.min(100, (used / total) * 100));
                bar.value = pct;

                var daysLeft = Math.ceil((end - now) / 86400000);
                if (now >= end) {
                    bar.className = "progress progress-error w-full";
                    lbl.textContent = "Expired";
                } else if (now < start) {
                    bar.className = "progress progress-info w-full";
                    lbl.textContent = "Not yet valid";
                } else {
                    if (pct >= 75) {
                        bar.className = "progress progress-warning w-full";
                    } else {
                        bar.className = "progress progress-success w-full";
                    }
                    lbl.textContent = daysLeft + " day" + (daysLeft !== 1 ? "s" : "") + " remaining";
                }
            } else {
                lbl.textContent = "Validity dates unavailable";
            }
        }
    }

    // Serial copy button
    const serialBtn = document.querySelector('button[data-serial]');
    if (serialBtn) {
        serialBtn.addEventListener('click', () => {
            const serial = serialBtn.dataset.serial;
            copySerial(serial);
        });
    }

    // Close button
    const closeBtn = document.querySelector('button[title="Close"]');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => window.close());
    }

    // P12 password modal bindings (if they exist on this page)
    const p12Btn = document.querySelector('button.btn-secondary');
    if (p12Btn && p12Btn.textContent.includes('Download P12')) {
        const orgId = p12Btn.getAttribute('data-org-id');
        const certId = p12Btn.getAttribute('data-cert-id');
        if (orgId && certId) {
            p12Btn.addEventListener('click', () => showP12Password(orgId, certId));
        }
    }

    // P12 modal copy button
    const p12CopyBtn = document.getElementById('p12CopyBtn');
    if (p12CopyBtn) {
        p12CopyBtn.addEventListener('click', copyP12Password);
    }

    // P12 modal close button
    const p12CloseBtn = document.querySelector('#p12PasswordModal button.btn-ghost:first-child');
    if (p12CloseBtn) {
        p12CloseBtn.addEventListener('click', () => p12PasswordModal.close());
    }
});
