function handleHasFixChange(checkbox) {
    const url = new URL(window.location.href);
    if (checkbox.checked) {
        url.searchParams.set('hasfix', 'true');
    } else {
        url.searchParams.delete('hasfix');
    }
    window.location.href = url.toString();
}

// Check hasfix URL parameter on page load
window.onload = function() {
    const url = new URL(window.location.href);
    const hasFixCheckbox = document.getElementById('hasFixCheckbox');
    if (hasFixCheckbox) {
        hasFixCheckbox.checked = url.searchParams.get('hasfix') === 'true';
    }
}