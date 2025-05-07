document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form');
    if (!form) return;

    form.addEventListener('submit', async function (event) {
        event.preventDefault();
        const formData = new FormData(form);

        try {
            const response = await fetch(form.action, {
                method: "POST",
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'  // Mark as AJAX request
                }
            });

            if (!response.ok) {
                throw new Error("Network response was not ok");
            }

            const result = await response.json();

            if (!result.success) {
                // Show popup for error
                alert(result.error || "Incorrect password. Please try again.");
            } else {
                // Success, show success popup and redirect
                alert(result.message || "Password updated successfully!");
                window.location.href = "/dashboard"; // Redirect to dashboard
            }
        } catch (error) {
            console.error('Error submitting form:', error);
            alert("Something went wrong. Please try again.");
        }
    });
});