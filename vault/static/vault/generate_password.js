function copyPassword() {
    const passwordText = document.getElementById('password').innerText;
    navigator.clipboard.writeText(passwordText).then(function() {
        alert("Password copied to clipboard!");
    }, function(err) {
        alert("Failed to copy: " + err);
    });
}