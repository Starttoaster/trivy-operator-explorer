// Get all unique resources from the table
function getUniqueResources() {
    const resources = new Set();
    document.querySelectorAll('td:nth-child(4)').forEach(cell => {
        resources.add(cell.textContent.trim());
    });
    return Array.from(resources).sort();
}

// Create and populate the resource filter dropdown in the sidebar
function createResourceFilter() {
    const resources = getUniqueResources();
    
    // Create container for the filter
    const container = document.createElement('div');
    container.className = 'p-2';
    
    // Create header with toggle button
    const header = document.createElement('div');
    header.className = 'flex items-center justify-between cursor-pointer';
    header.onclick = () => {
        const content = document.getElementById('resourceFilterContent');
        const icon = document.getElementById('resourceFilterIcon');
        if (content.style.display === 'none') {
            content.style.display = 'block';
            icon.style.transform = 'rotate(180deg)';
        } else {
            content.style.display = 'none';
            icon.style.transform = 'rotate(0deg)';
        }
    };
    
    // Create header text
    const headerText = document.createElement('span');
    headerText.className = 'text-sm font-medium text-gray-900 dark:text-gray-300';
    headerText.textContent = 'Resource Filter';
    
    // Create toggle icon
    const icon = document.createElement('svg');
    icon.id = 'resourceFilterIcon';
    icon.className = 'w-4 h-4 transition-transform';
    icon.style.transform = 'rotate(0deg)';
    icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>';
    
    header.appendChild(headerText);
    header.appendChild(icon);
    container.appendChild(header);
    
    // Create content container
    const content = document.createElement('div');
    content.id = 'resourceFilterContent';
    content.className = 'mt-2';
    content.style.display = 'none';
    
    // Create checkbox container
    const checkboxContainer = document.createElement('div');
    checkboxContainer.className = 'space-y-2 max-h-48 overflow-y-auto';
    
    // Add "All" checkbox
    const allCheckbox = document.createElement('div');
    allCheckbox.className = 'flex items-center';
    const allInput = document.createElement('input');
    allInput.type = 'checkbox';
    allInput.id = 'resource-all';
    allInput.value = 'all';
    allInput.className = 'w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600';
    allInput.checked = true;
    const allLabel = document.createElement('label');
    allLabel.htmlFor = 'resource-all';
    allLabel.className = 'ms-2 text-sm font-medium text-gray-900 dark:text-gray-300';
    allLabel.textContent = 'All Resources';
    allCheckbox.appendChild(allInput);
    allCheckbox.appendChild(allLabel);
    checkboxContainer.appendChild(allCheckbox);
    
    // Add resource checkboxes
    resources.forEach(resource => {
        const checkboxDiv = document.createElement('div');
        checkboxDiv.className = 'flex items-center';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.id = `resource-${resource}`;
        input.value = resource;
        input.className = 'w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600';
        const label = document.createElement('label');
        label.htmlFor = `resource-${resource}`;
        label.className = 'ms-2 text-sm font-medium text-gray-900 dark:text-gray-300';
        label.textContent = resource;
        checkboxDiv.appendChild(input);
        checkboxDiv.appendChild(label);
        checkboxContainer.appendChild(checkboxDiv);
    });
    
    // Add Apply button
    const buttonContainer = document.createElement('div');
    buttonContainer.className = 'mt-4 flex justify-end';
    const applyButton = document.createElement('button');
    applyButton.type = 'button';
    applyButton.className = 'text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:ring-blue-300 font-medium rounded-lg text-sm px-4 py-2 dark:bg-blue-600 dark:hover:bg-blue-700 focus:outline-none dark:focus:ring-blue-800';
    applyButton.textContent = 'Apply';
    applyButton.onclick = applyResourceFilter;
    buttonContainer.appendChild(applyButton);
    
    // Add change event listeners
    const checkboxes = checkboxContainer.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', handleCheckboxChange);
    });
    
    content.appendChild(checkboxContainer);
    content.appendChild(buttonContainer);
    container.appendChild(content);
    
    // Insert after the hasfix toggle
    const hasfixToggle = document.querySelector('input[type="checkbox"][id="hasFixCheckbox"]').closest('.p-2');
    if (hasfixToggle) {
        hasfixToggle.parentNode.insertBefore(container, hasfixToggle.nextSibling);
    }
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
    // Only create the filter on the image page
    if (window.location.pathname === '/image') {
        createResourceFilter();
        
        // Set initial selection based on URL parameters
        const url = new URL(window.location.href);
        const resourcesParam = url.searchParams.get('resources');
        if (resourcesParam) {
            const selectedResources = resourcesParam.split(',');
            const checkboxes = document.querySelectorAll('#resourceFilterContent input[type="checkbox"]');
            checkboxes.forEach(checkbox => {
                if (checkbox.id === 'resource-all') {
                    checkbox.checked = selectedResources.length === 0;
                } else {
                    checkbox.checked = selectedResources.includes(checkbox.value);
                }
            });
        }
    }
}); 