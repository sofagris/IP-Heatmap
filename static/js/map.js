// static/js/map.js

// Initialize the map
var map = L.map('map').setView([51.505, -0.09], 3);

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
    subdomains: 'abcd',
    maxZoom: 19
}).addTo(map);

// Variable to hold the country layer
let countryLayer;

// Function to load GeoJSON data
function loadGeoJSON() {
    const loadingModal = document.getElementById('loadingModal');

    fetch('/static/geojson/countries.geojson')
        .then(response => response.json())
        .then(data => {
            countryLayer = L.geoJSON(data, {
                style: {
                    color: "#000",
                    weight: 1,
                }
            }).addTo(map);

            // Remove loading modal when GeoJSON is loaded
            loadingModal.style.display = 'none';
        })
        .catch(error => {
            console.error('Error loading GeoJSON:', error);
            loadingModal.innerHTML = '<p>Error loading map data. Please try again later.</p>';
        });
}

// Load GeoJSON when DOM is ready
document.addEventListener('DOMContentLoaded', function () {
    loadGeoJSON();
});
