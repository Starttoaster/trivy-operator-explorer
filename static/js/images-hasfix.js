function handleHasFixChange(checkbox) {
    const url = new URL(window.location.href);
    if (checkbox.checked) {
        url.searchParams.set('hasfix', 'true');
    } else {
        url.searchParams.delete('hasfix');
    }
    window.location.href = url.toString();
}

function handleShowIgnoredChange(checkbox) {
    const url = new URL(window.location.href);
    if (checkbox.checked) {
        url.searchParams.set('showignored', 'true');
    } else {
        url.searchParams.delete('showignored');
    }
    window.location.href = url.toString();
}

// Check URL parameters on page load
window.onload = function() {
    const url = new URL(window.location.href);
    
    // Check hasfix parameter
    const hasFixCheckbox = document.getElementById('hasFixCheckbox');
    if (hasFixCheckbox) {
        hasFixCheckbox.checked = url.searchParams.get('hasfix') === 'true';
    }
    
    // Check showignored parameter
    const showIgnoredCheckbox = document.getElementById('showIgnoredCheckbox');
    if (showIgnoredCheckbox) {
        showIgnoredCheckbox.checked = url.searchParams.get('showignored') === 'true';
    }
}
