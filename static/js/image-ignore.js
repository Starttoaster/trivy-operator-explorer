document.addEventListener('DOMContentLoaded', function() {
    // Handle ignore button clicks
    document.addEventListener('click', function(e) {
        if (e.target.closest('.ignore-btn')) {
            e.preventDefault();
            e.stopPropagation();
            
            const button = e.target.closest('.ignore-btn');
            const dropdown = button.parentElement.querySelector('.ignore-dropdown');
            
            // Close all other dropdowns
            document.querySelectorAll('.ignore-dropdown').forEach(drop => {
                if (drop !== dropdown) {
                    drop.classList.add('hidden');
                }
            });
            
            // Toggle current dropdown
            const isHidden = dropdown.classList.contains('hidden');
            
            if (isHidden) {
                // Show dropdown first
                dropdown.classList.remove('hidden');
                
                // Create backdrop overlay
                const backdrop = document.createElement('div');
                backdrop.className = 'ignore-backdrop fixed inset-0 bg-black bg-opacity-25 z-40';
                backdrop.id = 'ignore-backdrop';
                document.body.appendChild(backdrop);
                
                // Position the dropdown relative to the button
                const buttonRect = button.getBoundingClientRect();
                const viewportWidth = window.innerWidth;
                const viewportHeight = window.innerHeight;
                
                // Get actual dropdown dimensions (now that it's visible)
                const dropdownRect = dropdown.getBoundingClientRect();
                
                // Calculate position - try to position to the right of the button
                let left = buttonRect.right + 10;
                let top = buttonRect.top;
                
                // If dropdown would go off the right edge, position to the left of the button
                if (left + dropdownRect.width > viewportWidth - 20) {
                    left = buttonRect.left - dropdownRect.width - 10;
                }
                
                // If dropdown would go off the bottom edge, adjust top position
                if (top + dropdownRect.height > viewportHeight - 20) {
                    top = viewportHeight - dropdownRect.height - 20;
                }
                
                // Ensure dropdown doesn't go off the top edge
                if (top < 20) {
                    top = 20;
                }
                
                // Ensure dropdown doesn't go off the left edge
                if (left < 20) {
                    left = 20;
                }
                
                // Final safety check - if still off screen, center it
                if (left + dropdownRect.width > viewportWidth || left < 0) {
                    left = (viewportWidth - dropdownRect.width) / 2;
                }
                
                if (top + dropdownRect.height > viewportHeight || top < 0) {
                    top = (viewportHeight - dropdownRect.height) / 2;
                }
                
                // Set final position
                dropdown.style.left = `${left}px`;
                dropdown.style.top = `${top}px`;
            } else {
                // Hide dropdown
                dropdown.classList.add('hidden');
                
                // Remove backdrop when hiding
                const backdrop = document.getElementById('ignore-backdrop');
                if (backdrop) {
                    backdrop.remove();
                }
            }
        }
        
        // Handle unignore button clicks
        if (e.target.closest('.unignore-btn')) {
            e.preventDefault();
            e.stopPropagation();
            
            const button = e.target.closest('.unignore-btn');
            
            // Get button data attributes
            const cveId = button.dataset.cveId;
            const registry = button.dataset.registry;
            const repository = button.dataset.repository;
            const tag = button.dataset.tag;
            
            // Confirm unignore action
            if (!confirm(`Are you sure you want to unignore CVE ${cveId}?`)) {
                return;
            }
            
            // Prepare request data
            const actualRegistry = registry || 'index.docker.io';
            
            const requestData = {
                registry: actualRegistry,
                repository: repository || '',
                tag: tag || '',
                cve_id: cveId
            };
            
            // Show loading state
            button.disabled = true;
            const originalHTML = button.innerHTML;
            button.innerHTML = '<svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>';
            
            // Send DELETE request to server
            fetch('/ignore', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            })
            .then(response => {
                if (response.ok) {
                    // Success - show success message and reload page
                    showSuccessMessage(`CVE ${cveId} has been unignored successfully.`);
                    // Reload page to refresh the view
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
            })
            .catch(error => {
                console.error('Error unignoring CVE:', error);
                showErrorMessage(`Failed to unignore CVE ${cveId}. Please try again.`);
            })
            .finally(() => {
                // Reset button state
                button.disabled = false;
                button.innerHTML = originalHTML;
            });
        }
        
        // Handle cancel button clicks
        if (e.target.closest('.cancel-btn')) {
            e.preventDefault();
            e.stopPropagation();
            
            const dropdown = e.target.closest('.ignore-dropdown');
            dropdown.classList.add('hidden');
            
            // Remove backdrop
            const backdrop = document.getElementById('ignore-backdrop');
            if (backdrop) {
                backdrop.remove();
            }
        }
    });
    
    // Handle form submissions
    document.addEventListener('submit', function(e) {
        if (e.target.closest('.ignore-form')) {
            e.preventDefault();
            e.stopPropagation();
            
            const form = e.target;
            const dropdown = form.closest('.ignore-dropdown');
            const button = dropdown.parentElement.querySelector('.ignore-btn');
            
            // Get form data
            const formData = new FormData(form);
            const reason = formData.get('reason');
            
            // Get button data attributes
            const cveId = button.dataset.cveId;
            const registry = button.dataset.registry;
            const repository = button.dataset.repository;
            const tag = button.dataset.tag;
            
            // Prepare request data
            // For Docker Hub images, use 'index.docker.io' as the registry
            const actualRegistry = registry || 'index.docker.io';
            
            const requestData = {
                registry: actualRegistry,
                repository: repository || '',
                tag: tag || '',
                cve_id: cveId,
                reason: reason,
            };
            
            // Show loading state
            const submitBtn = form.querySelector('.submit-btn');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = 'Ignoring...';
            submitBtn.disabled = true;
            
            // Send request to server
            fetch('/ignore', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            })
            .then(response => {
                if (response.ok) {
                    // Success - hide dropdown and show success message
                    dropdown.classList.add('hidden');
                    
                    // Remove backdrop
                    const backdrop = document.getElementById('ignore-backdrop');
                    if (backdrop) {
                        backdrop.remove();
                    }
                    
                    showSuccessMessage(`CVE ${cveId} has been ignored successfully.`);
                    
                    // Reset form
                    form.reset();
                } else {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
            })
            .catch(error => {
                console.error('Error ignoring CVE:', error);
                showErrorMessage(`Failed to ignore CVE ${cveId}. Please try again.`);
            })
            .finally(() => {
                // Reset button state
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
            });
        }
    });
    
    // Close dropdowns when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.ignore-btn') && !e.target.closest('.ignore-dropdown')) {
            document.querySelectorAll('.ignore-dropdown').forEach(dropdown => {
                dropdown.classList.add('hidden');
            });
            
            // Remove backdrop
            const backdrop = document.getElementById('ignore-backdrop');
            if (backdrop) {
                backdrop.remove();
            }
        }
    });
    
    // Handle escape key to close dropdowns
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.ignore-dropdown').forEach(dropdown => {
                dropdown.classList.add('hidden');
            });
            
            // Remove backdrop
            const backdrop = document.getElementById('ignore-backdrop');
            if (backdrop) {
                backdrop.remove();
            }
        }
    });
});

// Helper functions for showing messages
function showSuccessMessage(message) {
    showMessage(message, 'success');
}

function showErrorMessage(message) {
    showMessage(message, 'error');
}

function showMessage(message, type) {
    // Create message element
    const messageEl = document.createElement('div');
    messageEl.className = `fixed top-4 left-4 z-50 px-4 py-3 rounded-lg shadow-lg transition-all duration-300 ${
        type === 'success' 
            ? 'bg-green-100 text-green-800 border border-green-200 dark:bg-green-900 dark:text-green-200 dark:border-green-700'
            : 'bg-red-100 text-red-800 border border-red-200 dark:bg-red-900 dark:text-red-200 dark:border-red-700'
    }`;
    messageEl.textContent = message;
    
    // Add to page
    document.body.appendChild(messageEl);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        messageEl.style.opacity = '0';
        messageEl.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (messageEl.parentNode) {
                messageEl.parentNode.removeChild(messageEl);
            }
        }, 300);
    }, 5000);
}
