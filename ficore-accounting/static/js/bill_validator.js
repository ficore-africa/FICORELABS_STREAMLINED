class BillFormValidator {
    constructor() {
        this.initializeValidation();
    }

    initializeValidation() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupNumberInputs();
            this.setupFormSubmission();
            this.setupReminderToggle();
            this.setupDateValidation();
        });
    }

    setupNumberInputs() {
        document.querySelectorAll('.number-input').forEach(input => {
            this.formatNumberInput(input);
        });
    }

    formatNumberInput(input) {
        const isReminderDays = input.id === 'reminder_days' || input.id.startsWith('reminder_days_');
        
        input.addEventListener('input', (e) => {
            this.handleNumberInput(e.target, isReminderDays);
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasted = (e.clipboardData || window.clipboardData).getData('text');
            this.handlePastedNumber(input, pasted, isReminderDays);
        });

        input.addEventListener('blur', (e) => {
            this.validateNumberInput(e.target, isReminderDays);
        });
    }

    handleNumberInput(input, isReminderDays) {
        const cursor = input.selectionStart;
        const oldLength = input.value.length;
        
        let value = input.value.replace(/[^0-9.]/g, '');
        
        if (!value) {
            input.value = '';
            this.clearValidationState(input, isReminderDays);
            return;
        }

        if (isReminderDays) {
            let numValue = parseInt(value) || 0;
            numValue = Math.max(1, Math.min(30, numValue));
            input.value = numValue.toString();
            this.updateValidationState(input, numValue >= 1 && numValue <= 30, isReminderDays);
        } else {
            value = this.cleanDecimalInput(value);
            let numericValue = parseFloat(value) || 0;
            const isValid = numericValue >= 0 && numericValue <= 10000000000;
            if (isValid) {
                input.value = this.formatCurrency(numericValue);
            } else {
                numericValue = Math.max(0, Math.min(10000000000, numericValue));
                input.value = this.formatCurrency(numericValue);
            }
            this.updateValidationState(input, isValid, isReminderDays);
        }

        this.adjustCursorPosition(input, cursor, oldLength);
    }

    cleanDecimalInput(value) {
        const parts = value.split('.');
        if (parts.length > 2) {
            value = parts[0] + '.' + parts.slice(1).join('');
        }
        if (parts.length > 1) {
            parts[1] = parts[1].slice(0, 2);
            value = parts[0] + (parts[1] ? '.' + parts[1] : '');
        }
        return value;
    }

    formatCurrency(value) {
        return value.toLocaleString('en-US', {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        });
    }

    handlePastedNumber(input, pasted, isReminderDays) {
        const clean = pasted.replace(/[^0-9.]/g, '');
        if (!clean) return;

        if (isReminderDays) {
            let numValue = parseInt(clean) || 0;
            numValue = Math.max(1, Math.min(30, numValue));
            input.value = numValue.toString();
            this.updateValidationState(input, true, isReminderDays);
        } else {
            const cleanDecimal = this.cleanDecimalInput(clean);
            let numericValue = parseFloat(cleanDecimal) || 0;
            numericValue = Math.max(0, Math.min(10000000000, numericValue));
            input.value = this.formatCurrency(numericValue);
            this.updateValidationState(input, true, isReminderDays);
        }
    }

    validateNumberInput(input, isReminderDays) {
        if (!input.value) {
            this.clearValidationState(input, isReminderDays);
            return;
        }

        const value = input.value.replace(/[^0-9.]/g, '');
        
        if (isReminderDays) {
            const numValue = parseInt(value) || 0;
            const isValid = numValue >= 1 && numValue <= 30;
            input.value = numValue.toString();
            this.updateValidationState(input, isValid, isReminderDays);
        } else {
            const cleanDecimal = this.cleanDecimalInput(value);
            const numericValue = parseFloat(cleanDecimal) || 0;
            const isValid = numericValue >= 0 && numericValue <= 10000000000;
            input.value = this.formatCurrency(numericValue);
            this.updateValidationState(input, isValid, isReminderDays);
        }
    }

    updateValidationState(input, isValid, isReminderDays) {
        const helpElement = this.getHelpElement(input, isReminderDays);
        
        if (isValid) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            if (helpElement) {
                helpElement.textContent = isReminderDays ? 
                    "{{ trans('bill_reminder_days_example', default='Example: 7 for a reminder 7 days before due date') | e }}" :
                    "{{ trans('bill_amount_help', default='Enter amount without commas (e.g., 5000 or 5000.00)') | e }}";
            }
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            const invalidFeedback = input.nextElementSibling;
            if (invalidFeedback && invalidFeedback.classList.contains('invalid-feedback')) {
                invalidFeedback.style.display = 'block';
            }
        }
    }

    clearValidationState(input, isReminderDays) {
        input.classList.remove('is-valid', 'is-invalid');
        const helpElement = this.getHelpElement(input, isReminderDays);
        if (helpElement) {
            helpElement.textContent = isReminderDays ? 
                "{{ trans('bill_reminder_days_example', default='Example: 7 for a reminder 7 days before due date') | e }}" :
                "{{ trans('bill_amount_help', default='Enter amount without commas (e.g., 5000 or 5000.00)') | e }}";
        }
        const invalidFeedback = input.nextElementSibling;
        if (invalidFeedback && invalidFeedback.classList.contains('invalid-feedback')) {
            invalidFeedback.style.display = 'none';
        }
    }

    getHelpElement(input, isReminderDays) {
        const helpId = isReminderDays ? `reminder_days_help${input.id.replace('reminder_days', '')}` : `amount_help${input.id.replace('amount', '')}`;
        return document.getElementById(helpId);
    }

    adjustCursorPosition(input, cursor, oldLength) {
        const newLength = input.value.length;
        const delta = newLength - oldLength;
        input.setSelectionRange(cursor + delta, cursor + delta);
    }

    setupFormSubmission() {
        document.querySelectorAll('.validate-form').forEach(form => {
            form.addEventListener('submit', (e) => {
                if (!this.validateForm(form)) {
                    e.preventDefault();
                }
            });
        });
    }

    validateForm(form) {
        let isValid = true;
        const inputs = form.querySelectorAll('input, select');
        inputs.forEach(input => {
            if (input.classList.contains('number-input')) {
                const isReminderDays = input.id === 'reminder_days' || input.id.startsWith('reminder_days_');
                this.validateNumberInput(input, isReminderDays);
                if (input.classList.contains('is-invalid')) {
                    isValid = false;
                }
            } else if (input.hasAttribute('required') && !input.value.trim()) {
                input.classList.add('is-invalid');
                const invalidFeedback = input.nextElementSibling;
                if (invalidFeedback && invalidFeedback.classList.contains('invalid-feedback')) {
                    invalidFeedback.style.display = 'block';
                }
                isValid = false;
            } else {
                input.classList.remove('is-invalid');
                input.classList.add('is-valid');
                const invalidFeedback = input.nextElementSibling;
                if (invalidFeedback && invalidFeedback.classList.contains('invalid-feedback')) {
                    invalidFeedback.style.display = 'none';
                }
            }
        });
        return isValid;
    }

    setupReminderToggle() {
        document.querySelectorAll('.form-check-input[id^="send_email"]').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const form = e.target.closest('form');
                const container = form.querySelector('.reminder-days-container') || form.querySelector('#reminder_days_container');
                if (container) {
                    container.style.display = e.target.checked ? 'block' : 'none';
                }
            });
        });
    }

    setupDateValidation() {
        document.querySelectorAll('input[type="date"]').forEach(input => {
            input.addEventListener('change', (e) => {
                const today = new Date().toISOString().split('T')[0];
                if (e.target.value < today) {
                    e.target.classList.add('is-invalid');
                    const invalidFeedback = e.target.nextElementSibling;
                    if (invalidFeedback && invalidFeedback.classList.contains('invalid-feedback')) {
                        invalidFeedback.style.display = 'block';
                    }
                } else {
                    e.target.classList.remove('is-invalid');
                    e.target.classList.add('is-valid');
                    const invalidFeedback = e.target.nextElementSibling;
                    if (invalidFeedback && invalidFeedback.classList.contains('invalid-feedback')) {
                        invalidFeedback.style.display = 'none';
                    }
                }
            });
        });
    }
}

const billValidator = new BillFormValidator();
