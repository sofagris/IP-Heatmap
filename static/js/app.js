// static/js/app.js

// Function to add attack data to the table
function addAttackToTable(data) {
    const tableBody = document.getElementById('attack-table-body');
    // Check if the number of rows exceeds 100
    if (tableBody.rows.length >= 100) {
        tableBody.deleteRow(0);
    }

    const row = document.createElement('tr');

    // Flag image
    const flagCell = document.createElement('td');
    const flagImg = document.createElement('img');
    const countryCode = data.geoip_info.country ? data.geoip_info.country.toLowerCase() : 'unknown';
    flagImg.src = `/static/flags/png100px/${countryCode}.png`;
    flagImg.alt = data.country || "Unknown";
    flagImg.style.width = '20px';
    flagImg.style.height = 'auto';
    flagCell.appendChild(flagImg);

    // Click to zoom in on the country
    flagImg.style.cursor = 'pointer';
    flagImg.onclick = function() {
        map.setView([data.geoip_info.latitude, data.geoip_info.longitude], 8);
    };

    // Highlight country boundaries on hover
    flagImg.onmouseover = function() {
        if (countryLayer) {
            countryLayer.eachLayer(function(layer) {
                if (layer.feature.properties.ISO_A2 === data.geoip_info.country) {
                    layer.setStyle({
                        fillColor: 'yellow',
                        fillOpacity: 0.5,
                        color: 'red'
                    });
                }
            });
        }
    };

    // Reset style on mouse out
    flagImg.onmouseout = function() {
        if (countryLayer) {
            countryLayer.resetStyle();
        }
    };
    row.appendChild(flagCell);

    // Time of attack
    const timeCell = document.createElement('td');
    timeCell.textContent = new Date().toLocaleTimeString();
    row.appendChild(timeCell);

    // IP address
    const ipCell = document.createElement('td');
    ipCell.textContent = data.source_ip;
    row.appendChild(ipCell);

    // Port
    const portCell = document.createElement('td');
    portCell.textContent = data.dest_port || "N/A";
    portCell.style.cursor = 'pointer';
    portCell.onclick = async function() {
        try {
            const response = await fetch(`/service/${data.dest_port}`);
            if (!response.ok) {
                throw new Error(`Error fetching service data: ${response.statusText}`);
            }
            const portData = await response.json();
            console.log('Port data:', portData);

            if (portData.error) {
                alert(`Port ${data.dest_port} not found.`);
            } else {
                const servicesInfo = Array.isArray(portData.services)
                    ? portData.services.map(service => `(${service.transport_protocol}) ${service.service_name}: ${service.description}`).join('\n')
                    : `(${service.transport_protocol}) ${portData.service.service_name}: ${portData.service.description}`;
                
                alert(`Port ${data.dest_port} is used for:\n${servicesInfo}`);
            }
        } catch (error) {
            console.error('Failed to fetch port data:', error);
            alert(`Failed to fetch details for port ${data.dest_port}.`);
        }
    };
    row.appendChild(portCell);

    // Country
    const countryCell = document.createElement('td');
    countryCell.textContent = data.geoip_info.country || "Unknown";
    row.appendChild(countryCell);

    // City
    const cityCell = document.createElement('td');
    cityCell.textContent = data.geoip_info.city || "Unknown";
    row.appendChild(cityCell);

    // Organization
    const orgCell = document.createElement('td');
    orgCell.textContent = data.geoip_info.org || "Unknown";
    row.appendChild(orgCell);

    // Append row to table
    tableBody.appendChild(row);

    // Auto-scroll if enabled
    const autoscrollEnabled = document.getElementById('autoscroll-checkbox').checked;
    if (autoscrollEnabled) {
        const tableContainer = document.querySelector('.attack-table-container');
        tableContainer.scrollTop = tableContainer.scrollHeight;
    }
}

// Update number of connected clients
async function updateClientCount() {
    try {
        const response = await fetch('/api/connections');
        const clients = await response.json();
        document.getElementById('client-count').textContent = clients.length;
    } catch (error) {
        console.error('Failed to fetch client data:', error);
    }
}

// Fetch client data every 5 seconds
updateClientCount();
setInterval(updateClientCount, 5000);

// Fetch Top 10 Attackers
async function fetchTopAttackers() {
    try {
        const response = await fetch('/api/connections/top/dest_port');
        const topAttackers = await response.json();
        const tableBody = document.getElementById('top-talkers-table-body');

        // Clear existing rows
        tableBody.innerHTML = '';

        topAttackers.forEach(attacker => {
            const row = document.createElement('tr');

            // Flag cell
            const flagCell = document.createElement('td');
            const flagImg = document.createElement('img');
            const countryCode = attacker.geoip_info.country ? attacker.geoip_info.country.toLowerCase() : 'unknown';
            flagImg.src = `/static/flags/png100px/${countryCode}.png`;
            flagImg.alt = attacker.geoip_info.country || "Unknown";
            flagCell.appendChild(flagImg);
            row.appendChild(flagCell);

            // Source IP cell
            const ipCell = document.createElement('td');
            ipCell.textContent = attacker.source_ip || "N/A";
            ipCell.style.cursor = 'pointer';
            ipCell.onclick = function() {
                document.getElementById('ip-address').textContent = attacker.source_ip || "N/A";
                document.getElementById('hostname').textContent = attacker.hostname || "N/A";
                document.getElementById('first-observed').textContent = attacker.first_observed || "N/A";
                document.getElementById('last-observed').textContent = attacker.last_observed || "N/A";
                document.getElementById('total-attempts').textContent = attacker.count || "N/A";
                openAttackerModal();
            };
            row.appendChild(ipCell);

            // Count cell
            const countCell = document.createElement('td');
            countCell.textContent = attacker.count || "N/A";
            row.appendChild(countCell);

            // Country cell
            const countryCell = document.createElement('td');
            countryCell.textContent = attacker.geoip_info.country || "N/A";
            row.appendChild(countryCell);

            // City cell
            const cityCell = document.createElement('td');
            cityCell.textContent = attacker.geoip_info.city || "N/A";
            row.appendChild(cityCell);

            // Org cell
            const orgCell = document.createElement('td');
            orgCell.textContent = attacker.geoip_info.org || "N/A";
            row.appendChild(orgCell);

            // Append the row to the table body
            tableBody.appendChild(row);
        });
    } catch (error) {
        console.error('Failed to fetch top attackers:', error);
    }
}

// Call the function initially and set interval
fetchTopAttackers();
setInterval(fetchTopAttackers, 15000);

// Event listeners
document.addEventListener('DOMContentLoaded', function () {
    // Toggle attack table visibility
    const toggleTableBtn = document.getElementById('toggle-table-btn');
    const table = document.getElementById('attack-table-container');

    toggleTableBtn.addEventListener('click', function () {
        if (table.style.display === 'none') {
            table.style.display = '';
            toggleTableBtn.textContent = 'Hide Table';
        } else {
            table.style.display = 'none';
            toggleTableBtn.textContent = 'Show Table';
        }
    });

    // Handle displaying connected clients
    document.getElementById('ws-clients').addEventListener('click', function() {
        fetch('/api/connections')
            .then(response => response.json())
            .then(data => {
                const clientList = document.getElementById('client-list');
                clientList.innerHTML = '';

                data.forEach(client => {
                    const listItem = document.createElement('li');
                    listItem.textContent = `Client IP: ${client['x-forwarded-for']} (Host: ${client.client})`;
                    clientList.appendChild(listItem);
                });

                // Update client count
                const clientCount = data.length;
                document.getElementById('client-count').textContent = clientCount;

                // Show modal
                document.getElementById('client-modal').style.display = 'block';
            })
            .catch(error => console.error('Error fetching client data:', error));
    });
});
