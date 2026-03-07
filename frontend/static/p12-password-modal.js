(function () {
    function getP12ModalElements() {
        return {
            modal: document.getElementById("p12PasswordModal"),
            password: document.getElementById("p12Password"),
            downloadLink: document.getElementById("p12DownloadLink"),
            copyFeedback: document.getElementById("p12CopyFeedback"),
        };
    }

    function showP12CopyFeedback(message) {
        var elements = getP12ModalElements();
        if (!elements.copyFeedback) {
            return;
        }
        elements.copyFeedback.textContent = message;
        elements.copyFeedback.classList.remove("hidden");
    }

    window.showP12Password = async function showP12Password(orgId, certId) {
        var elements = getP12ModalElements();
        if (!elements.modal || !elements.password || !elements.downloadLink || !elements.copyFeedback) {
            alert("PKCS#12 download UI is unavailable.");
            return;
        }

        try {
            var resp = await fetch("/organizations/" + orgId + "/certificates/" + certId + "/p12-password");
            if (!resp.ok) {
                alert("Could not retrieve P12 password.");
                return;
            }

            var data = await resp.json();
            elements.password.textContent = data.password;
            elements.downloadLink.href =
                "/organizations/" + orgId + "/certificates/" + certId + "/download?format=p12";
            elements.copyFeedback.classList.add("hidden");
            elements.copyFeedback.textContent = "Copied to clipboard!";
            elements.modal.showModal();
        } catch (error) {
            alert("Error retrieving P12 password.");
        }
    };

    window.copyP12Password = function copyP12Password() {
        var elements = getP12ModalElements();
        if (!elements.password) {
            return;
        }

        if (!navigator.clipboard || !navigator.clipboard.writeText) {
            showP12CopyFeedback("Clipboard unavailable");
            return;
        }

        navigator.clipboard.writeText(elements.password.textContent).then(function () {
            showP12CopyFeedback("Copied to clipboard!");
        }).catch(function () {
            showP12CopyFeedback("Copy failed");
        });
    };
})();
