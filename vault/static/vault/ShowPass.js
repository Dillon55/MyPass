

function getCSRFToken() {
    const csrfTokenInput = document.querySelector('[name=csrfmiddlewaretoken]');
    return csrfTokenInput ? csrfTokenInput.value : null;
}

function showPassword(encryptedPassword, elementId) {
    // Get the element that will display the password
    const passwordElement = document.getElementById(elementId);
    
    // Prompt for account password
    const accountPassword = prompt("Enter your account password to view this password:");
    
    // Validate input
    if (!accountPassword) {
        alert("No password entered. Cannot show the password.");
        return;
    }
    
    // Visual indicator that decryption is in progress
    passwordElement.textContent = "Decrypting...";
    
    // Send request to decrypt
    fetch("/decrypt_password/", {  
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        },
        body: JSON.stringify({ 
            encrypted_password: encryptedPassword,
            account_password: accountPassword 
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Show the decrypted password
            passwordElement.textContent = data.decrypted_password;
            
            // Create a "Copy" button
            const copyButton = document.createElement('button');
            copyButton.textContent = 'Copy';
            copyButton.onclick = function() {
                navigator.clipboard.writeText(data.decrypted_password)
                    .then(() => {
                        copyButton.textContent = 'Copied!';
                        setTimeout(() => { copyButton.textContent = 'Copy'; }, 2000);
                    });
            };
            
            // Add the copy button next to the password element
            passwordElement.parentNode.insertBefore(copyButton, passwordElement.nextSibling);
            
            // Hide the password after a timeout
            setTimeout(() => {
                passwordElement.textContent = "******";
                if (copyButton.parentNode) {
                    copyButton.parentNode.removeChild(copyButton);
                }
            }, 30000); // Hide after 30 seconds
        } else {
            // Show error message
            passwordElement.textContent = "******";
            alert(data.error || "Failed to decrypt password. Check your account password.");
        }
    })
    .catch(error => {
        console.error("Error:", error);
        passwordElement.textContent = "******";
        alert("An error occurred. Please try again.");
    });
}
    
function confirmDeleteGroup(groupId) {
    if (!groupId) {
        alert("Invalid group ID");
        return;
    }

    const enteredPassword = prompt("Enter your account password to delete this group:");

    if (!enteredPassword) {
        alert("No password entered. Cannot delete the group.");
        return;
    }

    console.log("Deleting group with ID:", groupId);

    fetch("/delete_group/", {  
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        },
        body: JSON.stringify({ 
            account_password: enteredPassword, 
            group_id: groupId
        })
    })
    .then(response => {
        console.log("Response status:", response.status);
        return response.json();
    })
    .then(data => {
        console.log("Server response:", data);

        if (data.success) {
            alert("Group deleted successfully.");
            location.reload();
        } else {
            alert(data.error || "Error deleting group.");
        }
    })
    .catch(error => {
        console.error("Full error:", error);
        alert("An error occurred. Please try again.");
    });
}


function confirmDelete(passwordId) {
    if (!passwordId) {
        alert("Invalid password ID");
        return;
    }

    const enteredPassword = prompt("Enter your account password to delete this password:");

    if (!enteredPassword) {
        alert("No password entered. Cannot delete the password.");
        return;
    }

    console.log("Deleting password with ID:", passwordId);

    fetch("/delete-password/", {  
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        },
        body: JSON.stringify({ 
            account_password: enteredPassword, 
            _id: passwordId
        })
    })
    .then(response => {
        console.log("Response status:", response.status);
        return response.json();
    })
    .then(data => {
        console.log("Server response:", data);

        if (data.success) {
            alert("Password deleted successfully.");
            location.reload();
        } else {
            alert(data.error || "Error deleting password.");
        }
    })
    .catch(error => {
        console.error("Full error:", error);
        alert("An error occurred. Please try again.");
    });
}

function showPasswordEdit(encryptedPassword, inputId) {
    const passwordInput = document.getElementById(inputId);
    const accountPassword = prompt("Enter your account password to view this password:");

    if (!accountPassword) {
        alert("No password entered. Cannot show the password.");
        return;
    }

    passwordInput.value = "Decrypting...";
    passwordInput.setAttribute("readonly", true); // Keep it locked during decryption

    fetch("/decrypt_password/", {  
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCSRFToken()
        },
        body: JSON.stringify({ 
            encrypted_password: encryptedPassword,
            account_password: accountPassword 
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            passwordInput.value = data.decrypted_password;
            passwordInput.removeAttribute("readonly"); // Allow editing
            
            // Add a class to highlight that the field is now editable
            passwordInput.classList.add("editable");
            
            // Optionally, add a visual indication that the password is now visible
            const indicator = document.createElement('span');
            indicator.textContent = " (Password visible - will be re-encrypted on save)";
            indicator.className = "password-visible-indicator";
            indicator.style.color = "green";
            indicator.style.fontSize = "0.8em";
            
            // Remove any existing indicators first
            const existingIndicators = document.querySelectorAll('.password-visible-indicator');
            existingIndicators.forEach(el => el.remove());
            
            // Add the new indicator after the password input
            passwordInput.parentNode.insertBefore(indicator, passwordInput.nextSibling);
            
            // Optional: Set a timeout to clear the password after some time
            setTimeout(() => {
                if (document.contains(indicator)) {
                    indicator.remove();
                }
            }, 60000); // 60 seconds
        } else {
            passwordInput.value = "******";
            alert(data.error || "Failed to decrypt password. Check your account password.");
        }
    })
    .catch(error => {
        console.error("Error:", error);
        passwordInput.value = "******";
        alert("An error occurred. Please try again.");
    });

}

    function openSidebar() {
        document.getElementById("sidebar").style.width = "250px";
        document.getElementById("main").style.marginLeft = "250px";
    }
    
    function closeSidebar() {
        document.getElementById("sidebar").style.width = "0";
        document.getElementById("main").style.marginLeft = "0";
    }


    document.addEventListener('DOMContentLoaded', function() {
        // Find the password input field
        const passwordField = document.querySelector('input[name="password"]');
        
        if (!passwordField) return;
        
        // Create styles
        const style = document.createElement('style');
        style.textContent = `
            #password-strength-container {
                margin-top: 10px;
                margin-bottom: 15px;
                width: 100%;
                max-width: 400px;
            }
            #password-strength-meter {
                height: 10px;
                background-color: #eee;
                border-radius: 5px;
                margin-bottom: 5px;
                overflow: hidden;
            }
            #password-strength-bar {
                height: 100%;
                width: 0%;
                transition: width 0.3s ease-in-out, background-color 0.3s;
            }
            #password-strength-text {
                font-size: 14px;
                margin: 0;
                color: #666;
            }
        `;
        document.head.appendChild(style);
        
        // Create the password strength meter elements
        const strengthContainer = document.createElement('div');
        strengthContainer.id = 'password-strength-container';
        strengthContainer.innerHTML = `
            <div id="password-strength-meter">
                <div id="password-strength-bar"></div>
            </div>
            <p id="password-strength-text">Password strength: <span id="strength-value">None</span></p>
        `;
        
        // Insert the strength meter right after the password field
        passwordField.parentNode.insertBefore(strengthContainer, passwordField.nextSibling);
        
        // Get references to inserted elements
        const strengthBar = document.getElementById('password-strength-bar');
        const strengthText = document.getElementById('strength-value');
        
        passwordField.addEventListener('input', function() {
            const password = this.value;
            
            // Calculate strength score
            let score = calculatePasswordStrength(password);
            
            // Update the visual indicator
            updateStrengthMeter(score);
        });
        
        function calculatePasswordStrength(password) {
            if (password.length === 0) return 0;
            
            let score = 0;
            
            // Length check
            if (password.length >= 8) score += 1;
            if (password.length >= 12) score += 1;
            
            // Character variety checks
            if (/[A-Z]/.test(password)) score += 1;
            if (/[a-z]/.test(password)) score += 1;
            if (/[0-9]/.test(password)) score += 1;
            if (/[^A-Za-z0-9]/.test(password)) score += 1;
            
            // Normalize score to 0-4 range
            return Math.min(4, Math.floor(score / 1.5));
        }
        
        function updateStrengthMeter(score) {
            // Empty password
            if (passwordField.value.length === 0) {
                strengthBar.style.width = '0%';
                strengthBar.style.backgroundColor = '#eee';
                strengthText.textContent = 'None';
                return;
            }
            
            // Set appropriate style based on score
            switch(score) {
                case 0:
                    strengthBar.style.width = '20%';
                    strengthBar.style.backgroundColor = '#ff4d4d'; // Red
                    strengthText.textContent = 'Very Weak';
                    break;
                case 1:
                    strengthBar.style.width = '40%';
                    strengthBar.style.backgroundColor = '#ffa64d'; // Orange
                    strengthText.textContent = 'Weak';
                    break;
                case 2:
                    strengthBar.style.width = '60%';
                    strengthBar.style.backgroundColor = '#ffff4d'; // Yellow
                    strengthText.textContent = 'Medium';
                    break;
                case 3:
                    strengthBar.style.width = '80%';
                    strengthBar.style.backgroundColor = '#4dff4d'; // Green
                    strengthText.textContent = 'Strong';
                    break;
                case 4:
                    strengthBar.style.width = '100%';
                    strengthBar.style.backgroundColor = '#4d4dff'; // Blue
                    strengthText.textContent = 'Very Strong';
                    break;
            }
        }
    });



     


function searchPasswords() {
    console.log("Search function triggered");
    
    // Get the search term and convert to lowercase
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) {
        console.error("Search input element not found");
        return;
    }
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    console.log("Searching for:", searchTerm);
    
    // Get all standalone password boxes
    const standaloneBoxes = document.querySelectorAll('.password-box');
    
    // Get all group boxes
    const groupBoxes = document.querySelectorAll('.group-box');
    
    // Get the no results message element
    const noResults = document.getElementById('noResults');
    
    console.log("Found", standaloneBoxes.length, "standalone password boxes");
    console.log("Found", groupBoxes.length, "group boxes");
    
    // Track if we found any matches
    let foundMatch = false;
    
    // If search term is empty, show everything
    if (searchTerm === '') {
        clearSearch();
        return;
    }
    
    // Process standalone password boxes
    standaloneBoxes.forEach((box, index) => {
        // Get the service name from the strong tag (first child)
        const strongTag = box.querySelector('strong');
        const serviceName = strongTag ? strongTag.textContent.toLowerCase() : '';
        
        console.log(`Standalone box ${index + 1} service name: "${serviceName}"`);
        
        if (serviceName.includes(searchTerm)) {
            console.log(`  MATCH FOUND in standalone box ${index + 1}`);
            box.style.display = 'block';
            foundMatch = true;
        } else {
            box.style.display = 'none';
        }
    });
    
    // Process group boxes
    groupBoxes.forEach((group, groupIndex) => {
        const groupItems = group.querySelectorAll('li');
        let groupHasMatch = false;
        
        console.log(`Group ${groupIndex + 1} has ${groupItems.length} items`);
        
        // Check each password in the group
        groupItems.forEach((item, itemIndex) => {
            // The service name is at the beginning of the text content before the dash
            const itemText = item.textContent.trim();
            const serviceName = itemText.split('-')[0].trim().toLowerCase();
            
            console.log(`  Group item ${itemIndex + 1} service name: "${serviceName}"`);
            
            if (serviceName.includes(searchTerm)) {
                console.log(`    MATCH FOUND in Group ${groupIndex + 1}, Item ${itemIndex + 1}`);
                item.style.display = 'list-item';
                groupHasMatch = true;
                foundMatch = true;
            } else {
                item.style.display = 'none';
            }
        });
        
        // Keep the group visible, regardless of matches
        group.style.display = 'block';
        
        // Optional: Add a visual indicator if group has no visible items
        if (!groupHasMatch && groupItems.length > 0) {
            group.classList.add('no-matches');
        } else {
            group.classList.remove('no-matches');
        }
    });
    
    console.log("Overall match found:", foundMatch);
    
    // Show/hide no results message if it exists
    if (noResults) {
        noResults.style.display = foundMatch ? 'none' : 'block';
    }
}

/**
 * Function to clear search and reset display
 */
function clearSearch() {
    console.log("Clear search triggered");
    
    const searchInput = document.getElementById('searchInput');
    const noResults = document.getElementById('noResults');
    
    // Clear search input
    if (searchInput) {
        searchInput.value = '';
    }
    
    // Hide "no results" message
    if (noResults) {
        noResults.style.display = 'none';
    }
    
    // Reset standalone password boxes
    const passwordBoxes = document.querySelectorAll('.password-box');
    console.log("Found", passwordBoxes.length, "password boxes to reset");
    
    passwordBoxes.forEach(box => {
        box.style.display = 'block';
    });
    
    // Reset group items
    const groupItems = document.querySelectorAll('.group-box li');
    console.log("Found", groupItems.length, "group items to reset");
    
    groupItems.forEach(item => {
        item.style.display = 'list-item';
    });
    
    // Reset all groups and remove no-matches class
    const groups = document.querySelectorAll('.group-box');
    console.log("Found", groups.length, "groups to reset");
    
    groups.forEach(group => {
        group.style.display = 'block';
        group.classList.remove('no-matches');
    });
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM fully loaded, setting up search functionality");
    
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        console.log("Search input found, adding event listeners");
        
        // Add input event listener for real-time searching
        searchInput.addEventListener('input', searchPasswords);
        
        // Clear any previous results
        clearSearch();
    } else {
        console.error("Search input not found on page");
    }
});

function searchGroups() {
    console.log("Group search function triggered");
    
    // Get the search term and convert to lowercase
    const searchInput = document.getElementById('groupSearchInput');
    if (!searchInput) {
        console.error("Group search input element not found");
        return;
    }
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    console.log("Searching for groups with:", searchTerm);
    
    // Get all group boxes
    const groupBoxes = document.querySelectorAll('.group-box');
    
    // Get the no results message element
    const noResults = document.getElementById('noGroupResults');
    
    console.log("Found", groupBoxes.length, "group boxes");
    
    // Track if we found any matches
    let foundMatch = false;
    
    // If search term is empty, show everything
    if (searchTerm === '') {
        clearGroupSearch();
        return;
    }
    
    // Process group boxes
    groupBoxes.forEach((group, groupIndex) => {
        // Get the group name from the h3 tag
        const h3Tag = group.querySelector('h3');
        const groupName = h3Tag ? h3Tag.textContent.toLowerCase() : '';
        
        console.log(`Group ${groupIndex + 1} name: "${groupName}"`);
        
        if (groupName.includes(searchTerm)) {
            console.log(`  MATCH FOUND for group ${groupIndex + 1}`);
            group.style.display = 'block';
            foundMatch = true;
        } else {
            group.style.display = 'none';
        }
    });
    
    console.log("Overall match found:", foundMatch);
    
    // Show/hide no results message if it exists
    if (noResults) {
        noResults.style.display = foundMatch ? 'none' : 'block';
    }
}

/**
 * Function to clear group search and reset display
 */
function clearGroupSearch() {
    console.log("Clear group search triggered");
    
    const searchInput = document.getElementById('groupSearchInput');
    const noResults = document.getElementById('noGroupResults');
    
    // Clear search input
    if (searchInput) {
        searchInput.value = '';
    }
    
    // Hide "no results" message
    if (noResults) {
        noResults.style.display = 'none';
    }
    
    // Reset all groups
    const groups = document.querySelectorAll('.group-box');
    console.log("Found", groups.length, "groups to reset");
    
    groups.forEach(group => {
        group.style.display = 'block';
    });
}

// Add this to the existing DOMContentLoaded event listener
document.addEventListener('DOMContentLoaded', function() {
    // Existing code...
    
    // Add group search functionality
    const groupSearchInput = document.getElementById('groupSearchInput');
    if (groupSearchInput) {
        console.log("Group search input found, adding event listeners");
        
        // Add input event listener for real-time searching
        groupSearchInput.addEventListener('input', searchGroups);
        
        // Clear any previous results
        clearGroupSearch();
    } else {
        console.error("Group search input not found on page");
    }
});

// Toggle visibility of password section
function togglePasswordsVisibility() {
    const button = document.getElementById('togglePasswordsBtn');
    // Find the heading that contains "Saved Passwords"
    const passwordsHeading = Array.from(document.querySelectorAll('h2')).find(h2 => 
        h2.textContent.includes('Saved Passwords'));
    const passwordsContainer = document.querySelector('.passwords-container');
    const passwordsSearchContainer = document.querySelector('#searchInput').closest('.search-container');
    
    // Check if currently visible
    const isVisible = passwordsContainer.style.display !== 'none';
    
    if (isVisible) {
        // Hide passwords
        if (passwordsHeading) passwordsHeading.style.display = 'none';
        passwordsContainer.style.display = 'none';
        passwordsSearchContainer.style.display = 'none';
        button.textContent = 'Show Passwords';
        button.classList.add('active');
    } else {
        // Show passwords
        if (passwordsHeading) passwordsHeading.style.display = 'block';
        passwordsContainer.style.display = 'grid'; // Changed to grid as defined in CSS
        passwordsSearchContainer.style.display = 'block';
        
        // Reset any password boxes that might have stretched
        const passwordBoxes = document.querySelectorAll('.password-box');
        passwordBoxes.forEach(box => {
            box.style.width = ''; // Reset to CSS default
            box.style.maxWidth = ''; // Reset to CSS default
        });
        
        button.textContent = 'Hide Passwords';
        button.classList.remove('active');
    }
}

// Toggle visibility of groups section
function toggleGroupsVisibility() {
    const button = document.getElementById('toggleGroupsBtn');
    // Find the heading that contains "Groups"
    const groupsHeading = Array.from(document.querySelectorAll('h2')).find(h2 => 
        h2.textContent.includes('Groups'));
    const groupsContainer = document.querySelector('.groups-container');
    const groupsSearchContainer = document.querySelector('#groupSearchInput').closest('.search-container');
    
    // Check if currently visible
    const isVisible = groupsContainer.style.display !== 'none';
    
    if (isVisible) {
        // Hide groups
        if (groupsHeading) groupsHeading.style.display = 'none';
        groupsContainer.style.display = 'none';
        groupsSearchContainer.style.display = 'none';
        button.textContent = 'Show Groups';
        button.classList.add('active');
    } else {
        // Show groups
        if (groupsHeading) groupsHeading.style.display = 'block';
        groupsContainer.style.display = 'grid'; // Changed to grid as defined in CSS
        groupsSearchContainer.style.display = 'block';
        
        // Reset any group boxes that might have stretched
        const groupBoxes = document.querySelectorAll('.group-box');
        groupBoxes.forEach(box => {
            box.style.width = ''; // Reset to CSS default
            box.style.maxWidth = ''; // Reset to CSS default
        });
        
        button.textContent = 'Hide Groups';
        button.classList.remove('active');
    }
}