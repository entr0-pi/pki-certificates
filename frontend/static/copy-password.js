function copyPassword() {
    const passwordElement = document.getElementById('passwordDisplay');
    const password = passwordElement.textContent;

    navigator.clipboard.writeText(password).then(() => {
        const feedback = document.getElementById('copyFeedback');
        feedback.classList.remove('hidden');
        setTimeout(() => {
            feedback.classList.add('hidden');
        }, 2000);
    }).catch(() => {
        alert('Failed to copy. Please copy manually.');
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const copyBtn = document.querySelector('button[class*="btn-outline"]');
    if (copyBtn && copyBtn.textContent.includes('Copy')) {
        copyBtn.addEventListener('click', copyPassword);
    }
});
