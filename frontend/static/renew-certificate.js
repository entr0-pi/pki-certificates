const form = document.querySelector('form');
const enddateInput = document.getElementById('enddate');
const daysRadio = document.getElementById('duration_days_radio');
const dateRadio = document.getElementById('duration_date_radio');
const daysInputDiv = document.getElementById('days-input-renewal');
const dateInputDiv = document.getElementById('date-input-renewal');
const daysInput = document.getElementById('enddate_days');
const dateInput = document.getElementById('enddate_date');

function updateEndDate() {
    const checkedRadio = form.querySelector('input[name="duration_type"]:checked');
    if (checkedRadio.value === "days") {
        const days = parseInt(daysInput.value || "365");
        const date = new Date();
        date.setDate(date.getDate() + days);
        enddateInput.value = date.toISOString().replace(/[-:TZ.]/g, '').slice(0, 14) + 'Z';
    } else {
        if (dateInput.value) {
            const date = new Date(dateInput.value + 'T00:00:00Z');
            enddateInput.value = date.toISOString().replace(/[-:TZ.]/g, '').slice(0, 14) + 'Z';
        }
    }
}

daysRadio.addEventListener('change', () => {
    daysInputDiv.classList.remove('hidden');
    dateInputDiv.classList.add('hidden');
    updateEndDate();
});

dateRadio.addEventListener('change', () => {
    daysInputDiv.classList.add('hidden');
    dateInputDiv.classList.remove('hidden');
    updateEndDate();
});

daysInput.addEventListener('input', updateEndDate);
dateInput.addEventListener('change', updateEndDate);

updateEndDate();
