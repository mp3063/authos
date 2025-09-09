<div class="bg-gray-50 dark:bg-gray-900 rounded border">
    <pre id="json-content" class="font-mono text-xs p-4 overflow-x-auto" style="line-height: 1.4; margin: 0;">{{ $json }}</pre>
</div>

<script>
function copyJsonContent() {
    const jsonElement = document.getElementById('json-content');
    
    if (jsonElement) {
        const text = jsonElement.textContent || jsonElement.innerText;
        
        // Try modern Clipboard API first
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
                showCopySuccess();
            }).catch(err => {
                console.warn('Modern clipboard API failed, trying fallback:', err);
                copyToClipboardFallback(text);
            });
        } else {
            // Fallback for older browsers
            copyToClipboardFallback(text);
        }
    } else {
        alert('JSON element not found!');
    }
}

function showCopySuccess() {
    // Show Filament notification if available
    if (window.$tooltip) {
        window.$tooltip('JSON copied to clipboard!', {
            theme: window.$store?.theme || 'dark',
            timeout: 2000,
        });
    } else {
        alert('JSON copied to clipboard!');
    }
}

function copyToClipboardFallback(text) {
    try {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        textArea.setSelectionRange(0, 99999); // For mobile devices
        
        const result = document.execCommand('copy');
        document.body.removeChild(textArea);
        
        if (result) {
            showCopySuccess();
        } else {
            alert('Copy failed - please manually select and copy the text');
        }
    } catch (err) {
        console.error('Fallback copy failed:', err);
        alert('Copy failed: ' + err.message);
    }
}
</script>