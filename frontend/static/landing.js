// Organization name character counter
const orgNameInput = document.getElementById("org_display_name");
const orgNameCount = document.getElementById("orgNameCount");

if (orgNameInput) {
    orgNameInput.addEventListener("input", () => {
        orgNameCount.textContent = orgNameInput.value.length;
    });
}

// Modal button bindings
document.addEventListener('DOMContentLoaded', () => {
    // Create Organization buttons
    document.getElementById('createOrgBtn')?.addEventListener('click', () => createOrgModal.showModal());
    document.getElementById('createFirstOrgBtn')?.addEventListener('click', () => createOrgModal.showModal());
    document.getElementById('createOrgCancelBtn')?.addEventListener('click', () => createOrgModal.close());

    // Consistency check button
    document.getElementById('consistencyCheckBtn')?.addEventListener('click', runConsistencyCheck);
    document.getElementById('consistencyCheckCloseBtn')?.addEventListener('click', () => consistencyCheckModal.close());
});
