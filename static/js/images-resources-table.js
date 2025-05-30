function toggleResources(digest) {
    const resourcesRow = document.getElementById(`resources-${digest}`);
    const icon = document.getElementById(`icon-${digest}`);
    
    if (resourcesRow.classList.contains('hidden')) {
        resourcesRow.classList.remove('hidden');
        icon.classList.add('rotate-180');
    } else {
        resourcesRow.classList.add('hidden');
        icon.classList.remove('rotate-180');
    }
}
