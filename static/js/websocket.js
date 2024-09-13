// static/js/websocket.js

let ws;

// Function to connect to WebSocket
function connectWebSocket() {
    const hostname = window.location.hostname;
    const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    const port = window.location.port ? window.location.port : (window.location.protocol === 'https:' ? '443' : '80');
    const wsUrl = `${protocol}${hostname}:${port}/ws`;

    // Add a pulse effect to the disconnected icon
    document.getElementById('ws-disconnected').classList.add('blink');

    ws = new WebSocket(wsUrl);

    ws.onopen = function(event) {
        console.log('WebSocket connection established at: '+ wsUrl );
        document.getElementById('ws-connected').classList.remove('hidden');
        document.getElementById('ws-connected').title = `Connected to ${wsUrl}`;
        document.getElementById('ws-disconnected').classList.add('hidden');
        // Remove the pulse class from the disconnected icon
        document.getElementById('ws-disconnected').classList.remove('blink');
    };

    ws.onmessage = function(event) {
        console.log('WebSocket message received');
        const data = JSON.parse(event.data);
        console.log('Received data:', data);

        if (data.geoip_info.latitude && data.geoip_info.longitude) {
            const latLng = [data.geoip_info.latitude, data.geoip_info.longitude];
            console.log('Creating ripple effect at:', latLng);

            const rippleDiv = document.createElement('div');
            rippleDiv.className = 'ripple';
            console.log('Ripple div created:', rippleDiv);

            const marker = L.marker(latLng, {
                icon: L.divIcon({
                    className: 'ripple-container',
                    html: rippleDiv.outerHTML,
                    iconSize: [30, 30]
                })
            }).addTo(map);

            console.log('Marker added to map:', marker);

            setTimeout(() => {
                map.removeLayer(marker);
                console.log('Marker removed from map:', marker);
            }, 1000); // Show ripple-effect for 1 second

            addAttackToTable(data);
        } else {
            console.error('GeoIP data incomplete:', data);
        }
    };

    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
    };

    ws.onclose = function(event) {
        console.log('WebSocket connection closed. Attempting to reconnect...');
        document.getElementById('ws-connected').classList.add('hidden');
        document.getElementById('ws-disconnected').title = `Disconnected from ${wsUrl}`;
        document.getElementById('ws-disconnected').classList.remove('hidden');
        setTimeout(connectWebSocket, 5000); // Try to reconnect after 5 seconds
    };
}

// Start WebSocket connection
connectWebSocket();
