document.addEventListener('DOMContentLoaded', function() {
    // Bulk selection state
    let selectedCVEs = new Set();
    
    // Initialize bulk action bar state
    updateBulkActionBar();
    
    // Update bulk action bar visibility and count
    function updateBulkActionBar() {
        const bulkActionBar = document.getElementById('bulk-action-bar');
        const countElement = document.getElementById('bulk-selection-count');
        const selectAllCheckbox = document.getElementById('select-all-checkbox');
        
        if (selectedCVEs.size > 0) {
            bulkActionBar.classList.remove('hidden');
            countElement.textContent = `${selectedCVEs.size} selected`;
        } else {
            bulkActionBar.classList.add('hidden');
        }
        
        // Update select all checkbox state
        const allCheckboxes = document.querySelectorAll('.cve-checkbox:not(:disabled)');
        if (selectAllCheckbox) {
            if (allCheckboxes.length > 0) {
                const checkedCount = document.querySelectorAll('.cve-checkbox:checked').length;
                selectAllCheckbox.checked = checkedCount === allCheckboxes.length;
                selectAllCheckbox.indeterminate = checkedCount > 0 && checkedCount < allCheckboxes.length;
                selectAllCheckbox.disabled = false;
            } else {
                selectAllCheckbox.checked = false;
                selectAllCheckbox.indeterminate = false;
                selectAllCheckbox.disabled = true;
            }
        }
    }
    
    // Handle individual checkbox changes
    document.addEventListener('change', function(e) {
        if (e.target.classList.contains('cve-checkbox')) {
            const checkbox = e.target;
            const cveId = checkbox.dataset.cveId;
            
            if (checkbox.checked) {
                selectedCVEs.add(cveId);
            } else {
                selectedCVEs.delete(cveId);
            }
            
            updateBulkActionBar();
        }
        
        // Handle select all checkbox
        if (e.target.id === 'select-all-checkbox') {
            const selectAll = e.target.checked;
            const checkboxes = document.querySelectorAll('.cve-checkbox:not(:disabled)');
            
            checkboxes.forEach(checkbox => {
                checkbox.checked = selectAll;
                const cveId = checkbox.dataset.cveId;
                if (selectAll) {
                    selectedCVEs.add(cveId);
                } else {
                    selectedCVEs.delete(cveId);
                }
            });
            
            updateBulkActionBar();
        }
    });
    
    // Handle clear selection button
    document.addEventListener('click', function(e) {
        if (e.target.id === 'bulk-clear-selection-btn') {
            selectedCVEs.clear();
            document.querySelectorAll('.cve-checkbox').forEach(checkbox => {
                checkbox.checked = false;
            });
            const selectAllCheckbox = document.getElementById('select-all-checkbox');
            if (selectAllCheckbox) {
                selectAllCheckbox.checked = false;
                selectAllCheckbox.indeterminate = false;
            }
            updateBulkActionBar();
        }
        
        // Handle bulk ignore button click
        if (e.target.id === 'bulk-ignore-btn') {
            e.preventDefault();
            e.stopPropagation();
            
            if (selectedCVEs.size === 0) {
                return;
            }
            
            const modal = document.getElementById('bulk-ignore-modal');
            const countElement = document.getElementById('bulk-cve-count');
            countElement.textContent = selectedCVEs.size;
            modal.classList.remove('hidden');
        }
        
        // Handle bulk cancel button
        if (e.target.id === 'bulk-cancel-btn') {
            const modal = document.getElementById('bulk-ignore-modal');
            modal.classList.add('hidden');
            document.getElementById('bulk-ignore-form').reset();
        }
        
        // Close bulk modal when clicking on backdrop (but not on modal content)
        const modal = document.getElementById('bulk-ignore-modal');
        if (e.target === modal) {
            modal.classList.add('hidden');
            document.getElementById('bulk-ignore-form').reset();
        }
    });
    
    // Handle bulk ignore form submission
    document.addEventListener('submit', function(e) {
        if (e.target.id === 'bulk-ignore-form') {
            e.preventDefault();
            e.stopPropagation();
            
            if (selectedCVEs.size === 0) {
                return;
            }
            
            const form = e.target;
            const formData = new FormData(form);
            const reason = formData.get('reason');
            
            if (!reason || reason.trim() === '') {
                showErrorMessage('Please provide a reason for ignoring these CVEs.');
                return;
            }
            
            // Get image info from first selected checkbox
            const firstCheckbox = document.querySelector('.cve-checkbox:checked');
            if (!firstCheckbox) {
                return;
            }
            
            const registry = firstCheckbox.dataset.registry || 'index.docker.io';
            const repository = firstCheckbox.dataset.repository || '';
            const tag = firstCheckbox.dataset.tag || '';
            
            // Prepare request data with array of CVE IDs
            const requestData = {
                registry: registry,
                repository: repository,
                tag: tag,
                cve_ids: Array.from(selectedCVEs),
                reason: reason,
            };
            
            // Show loading state
            const submitBtn = document.getElementById('bulk-submit-btn');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = 'Ignoring...';
            submitBtn.disabled = true;
            
            // Send request to server
            fetch('/ignore/bulk', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            })
            .then(response => {
                if (response.ok) {
                    // Success - show success message and reload page
                    showSuccessMessage(`${selectedCVEs.size} CVEs have been ignored successfully.`);
                    
                    // Reload page to refresh the view, preserving URL parameters
                    setTimeout(() => {
                        window.location.href = window.location.href;
                    }, 1000);
                } else {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
            })
            .catch(error => {
                console.error('Error ignoring CVEs:', error);
                showErrorMessage(`Failed to ignore CVEs. Please try again.`);
            })
            .finally(() => {
                // Reset button state
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
            });
        }
    });
    
    // Handle unignore button clicks
    document.addEventListener('click', function(e) {
        if (e.target.closest('.unignore-btn')) {
            e.preventDefault();
            e.stopPropagation();
            
            const button = e.target.closest('.unignore-btn');
            
            // Get button data attributes
            const cveId = button.dataset.cveId;
            const registry = button.dataset.registry;
            const repository = button.dataset.repository;
            const tag = button.dataset.tag;
            const reason = button.dataset.reason;
            
            // Confirm unignore action
            if (!confirm(`Are you sure you want to unignore ${cveId}?\nCurrently ignored for reason:\n${reason}`)) {
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
                    // Reload page to refresh the view, preserving URL parameters
                    setTimeout(() => {
                        window.location.href = window.location.href;
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
    });
    
    // Handle escape key to close bulk modal
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            // Close bulk modal
            const bulkModal = document.getElementById('bulk-ignore-modal');
            if (bulkModal && !bulkModal.classList.contains('hidden')) {
                bulkModal.classList.add('hidden');
                document.getElementById('bulk-ignore-form').reset();
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
