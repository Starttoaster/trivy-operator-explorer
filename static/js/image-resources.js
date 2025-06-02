// Get all unique resources from the table
function getUniqueResources() {
    const resources = new Set();
    document.querySelectorAll('td:nth-child(4)').forEach(cell => {
        resources.add(cell.textContent.trim());
    });
    return Array.from(resources).sort();
}

// Select all resource checkboxes
function selectAllResources() {
    const checkboxes = document.querySelectorAll('#resourceFilterContent input[type="checkbox"]');
    const allCheckbox = document.getElementById('resource-all');
    
    // Check if all checkboxes are currently checked
    const allChecked = Array.from(checkboxes).every(checkbox => 
        checkbox.id === 'resource-all' || checkbox.checked
    );
    
    // Uncheck the "All" checkbox
    allCheckbox.checked = false;
    
    // Toggle all other checkboxes based on current state
    checkboxes.forEach(checkbox => {
        if (checkbox.id !== 'resource-all') {
            checkbox.checked = !allChecked;
        }
    });
}

// Toggle the resource filter visibility
function toggleResourceFilter() {
    const content = document.getElementById('resourceFilterContent');
    const icon = document.getElementById('resourceFilterIcon');
    if (content.style.display === 'none') {
        content.style.display = 'block';
        icon.style.transform = 'rotate(180deg)';
    } else {
        content.style.display = 'none';
        icon.style.transform = 'rotate(0deg)';
    }
}

// Populate the resource checkboxes
function populateResourceCheckboxes() {
    const resources = getUniqueResources();
    const container = document.querySelector('#resourceFilterContent .space-y-2');
    
    resources.forEach(resource => {
        const checkboxDiv = document.createElement('div');
        checkboxDiv.className = 'flex items-center min-w-max';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.id = `resource-${resource}`;
        input.value = resource;
        input.className = 'w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600 shrink-0';
        const label = document.createElement('label');
        label.htmlFor = `resource-${resource}`;
        label.className = 'ms-2 text-sm font-medium text-gray-900 dark:text-gray-300 truncate';
        label.textContent = resource;
        checkboxDiv.appendChild(input);
        checkboxDiv.appendChild(label);
        container.appendChild(checkboxDiv);
    });
}

// Handle checkbox changes
function handleCheckboxChange(event) {
    const checkboxes = document.querySelectorAll('#resourceFilterContent input[type="checkbox"]');
    const allCheckbox = document.getElementById('resource-all');
    
    if (event.target.id === 'resource-all') {
        // If "All" is checked, uncheck all others
        if (event.target.checked) {
            checkboxes.forEach(checkbox => {
                if (checkbox.id !== 'resource-all') {
                    checkbox.checked = false;
                }
            });
        }
    } else {
        // If a specific resource is checked, uncheck "All"
        if (event.target.checked) {
            allCheckbox.checked = false;
        }
        
        // If no specific resources are checked, check "All"
        const anyChecked = Array.from(checkboxes).some(checkbox => 
            checkbox.id !== 'resource-all' && checkbox.checked
        );
        allCheckbox.checked = !anyChecked;
    }
}

// Apply the resource filter
function applyResourceFilter() {
    const checkboxes = document.querySelectorAll('#resourceFilterContent input[type="checkbox"]');
    const selectedValues = Array.from(checkboxes)
        .filter(checkbox => checkbox.checked)
        .map(checkbox => checkbox.value);
    
    const url = new URL(window.location.href);
    if (selectedValues.length === 1 && selectedValues[0] === 'all') {
        url.searchParams.delete('resources');
    } else {
        url.searchParams.set('resources', selectedValues.filter(v => v !== 'all').join(','));
    }
    window.location.href = url.toString();
}

// Initialize the resource filter when the page loads
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize on the image page
    if (window.location.pathname === '/image') {
        // Add change event listeners to checkboxes
        const checkboxes = document.querySelectorAll('#resourceFilterContent input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', handleCheckboxChange);
        });
        
        // Populate resource checkboxes
        populateResourceCheckboxes();
        
        // Set initial selection based on URL parameters
        const url = new URL(window.location.href);
        const resourcesParam = url.searchParams.get('resources');
        const allCheckbox = document.getElementById('resource-all');
        
        if (resourcesParam) {
            const selectedResources = resourcesParam.split(',');
            checkboxes.forEach(checkbox => {
                if (checkbox.id === 'resource-all') {
                    checkbox.checked = false;
                } else {
                    checkbox.checked = selectedResources.includes(checkbox.value);
                }
            });
        } else {
            // If no resources parameter, hide the "All" option
            allCheckbox.closest('.flex.items-center').style.display = 'none';
        }

        // Ensure the Select All button is visible
        const selectAllButton = document.querySelector('#resourceFilterContent button[onclick="selectAllResources()"]');
        if (selectAllButton) {
            selectAllButton.style.display = 'block';
        }
    }
}); 