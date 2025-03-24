// src/lib/clientLogger.js
export function log(message: any, level = 'info') {
    // Still log to browser console
    console.log(message);

    // Also send to server
    fetch('/debug/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            level,
            message: typeof message === 'object' ? JSON.stringify(message) : message,
            source: window.location.pathname
        })
    }).catch(e => console.error('Failed to send log to server:', e));
}