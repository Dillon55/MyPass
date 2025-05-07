document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form');
    if (!form) return;

    //Find the account password field
    //You might need to adjust this selector depending on your form structure
    const accountPasswordField = form.querySelector('input[name="account_password"]');

    if (!accountPasswordField) {
        console.warn('Account password field not found in the form');
        return;
    }

    form.addEventListener('submit', async function (event) {
        event.preventDefault();
        
        const accountPassword = accountPasswordField.value;
        
        if (!accountPassword) {
            alert('Please enter your account password.');
            return;
        }
        
        try {
            //First verify if the account password is correct
            const verifyResponse = await fetch('/verify_account_password/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({
                    account_password: accountPassword
                })
            });
            
            const verifyResult = await verifyResponse.json();
            
            if (!verifyResult.success) {
                //Password verification failed
                alert(verifyResult.error || 'Incorrect account password. Please try again.');
                return;
            }
            
            //Password is correct, proceed with form submission
            form.submit();
            
        } catch (error) {
            console.error('Error verifying password:', error);
            alert('Something went wrong while verifying your password. Please try again.');
        }
    });
    
    //Helper function to get CSRF token from cookies
    function getCsrfToken() {
        const name = 'csrftoken';
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
    }
});