function sanitizeID(id) {
    return id.replace(/[^a-zA-Z0-9]/g, '_');
}

function toggleResources(imageName) {
    const safeId = sanitizeID(imageName);    
    const resourcesRow = document.getElementById(`resources-${safeId}`);
    const icon = document.getElementById(`icon-${safeId}`);
    
    if (!resourcesRow || !icon) {
        console.error('Could not find elements with IDs:', {
            resourcesId: `resources-${safeId}`,
            iconId: `icon-${safeId}`
        });
        return;
    }
    
    if (resourcesRow.classList.contains('hidden')) {
        resourcesRow.classList.remove('hidden');
        icon.classList.add('rotate-180');
    } else {
        resourcesRow.classList.add('hidden');
        icon.classList.remove('rotate-180');
    }
}
