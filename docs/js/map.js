/* ============================================================
   map.js — AU Threat Map v3
   City clusters only — all threats shown, no performance cap
   ============================================================ */

let map, mLayer;

const AU_BOUNDS = L.latLngBounds(
    L.latLng(-44.0, 112.0),
    L.latLng(-9.5, 154.5)
);

const CITY_COORDS = {
    'Perth': [-31.9505, 115.8605],
    'Darwin': [-12.4634, 130.8456],
    'Adelaide': [-34.9285, 138.6007],
    'Brisbane': [-27.4698, 153.0251],
    'Sydney': [-33.8688, 151.2093],
    'Melbourne': [-37.8136, 144.9631],
    'Hobart': [-42.8821, 147.3272],
    'Canberra': [-35.2809, 149.1300],
    'Gold Coast': [-28.0167, 153.4000],
    'Newcastle': [-32.9267, 151.7789],
};

function initMap() {
    map = L.map('auMap', {
        center: [-27.0, 133.5],
        zoom: 4,
        minZoom: 4,
        maxZoom: 10,
        maxBounds: AU_BOUNDS,
        maxBoundsViscosity: 1.0,
        zoomControl: true,
        attributionControl: false,
    });

    // CARTO dark basemap — designed for dark dashboards, so it stays
    // legible at high opacity (unlike the default OSM bright style,
    // which becomes nearly invisible when dimmed enough to match a
    // dark theme — that's why the coastline disappeared previously).
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 18,
        opacity: 0.85,
        subdomains: 'abcd',
    }).addTo(map);

    // State labels
    [['WA', -25.5, 121.6], ['NT', -19.5, 133.5], ['SA', -30.0, 135.5],
    ['QLD', -22.5, 144.5], ['NSW', -32.5, 146.5], ['VIC', -37.0, 144.8],
    ['TAS', -42.0, 146.5], ['ACT', -35.5, 149.1]
    ].forEach(([name, lat, lng]) => {
        L.marker([lat, lng], {
            icon: L.divIcon({
                className: '',
                html: `<div style="font-size:9px;font-weight:700;color:rgba(120,160,200,0.35);
                    letter-spacing:1.5px;pointer-events:none;user-select:none">${name}</div>`,
                iconSize: [30, 14], iconAnchor: [15, 7],
            }),
            interactive: false,
        }).addTo(map);
    });

    mLayer = L.layerGroup().addTo(map);
    window.map = map;

    // Mini legend bottom-left
    const legend = L.control({ position: 'bottomleft' });
    legend.onAdd = () => {
        const div = L.DomUtil.create('div');
        div.style.cssText = `background:rgba(7,11,28,.85);border:1px solid #1a2d45;
            border-radius:6px;padding:7px 10px;font-size:9.5px;font-family:monospace;
            color:#7a9cc8;line-height:1.9`;
        div.innerHTML = `
            <div style="color:#cde0ff;font-weight:700;margin-bottom:3px;letter-spacing:.5px">THREAT LEVEL</div>
            <div><span style="color:#ff3d5a">●</span> Majority Critical</div>
            <div><span style="color:#ff9800">●</span> Majority High</div>
            <div><span style="color:#2979ff">●</span> Mixed / Lower</div>
            <div style="margin-top:4px;color:#3a5878;font-size:8.5px">Click bubble for details<br>Bubble size = threat volume</div>`;
        return div;
    };
    legend.addTo(map);
}

function renderMap(threats) {
    if (!map) return;
    mLayer.clearLayers();

    // Group ALL threats by city — no cap
    const cityGroups = {};
    const cityMaxCvss = {};
    const cityCritCount = {};

    (threats || []).forEach(t => {
        const city = t.city;
        if (!city || city === 'AU' || city === 'Unknown' || !CITY_COORDS[city]) return;
        cityGroups[city] = (cityGroups[city] || 0) + 1;
        cityMaxCvss[city] = Math.max(cityMaxCvss[city] || 0, t.cvss_score || 0);
        cityCritCount[city] = (cityCritCount[city] || 0) + (t.severity === 'Critical' ? 1 : 0);
    });

    const totalMapped = Object.values(cityGroups).reduce((a, b) => a + b, 0);
    const maxCount = Math.max(...Object.values(cityGroups), 1);

    Object.entries(cityGroups).forEach(([city, count]) => {
        const coords = CITY_COORDS[city];
        const critPct = (cityCritCount[city] || 0) / count;
        const ratio = count / maxCount;

        // Colour: red if mostly critical, orange if mostly high, else blue
        const col = critPct > 0.5 ? '#ff3d5a'
            : cityMaxCvss[city] >= 7 ? '#ff9800'
                : '#2979ff';

        // Bubble size: 18–52px based on relative count
        const r = Math.round(18 + ratio * 34);

        // Pulse ring
        L.marker(coords, {
            icon: L.divIcon({
                className: '',
                html: `<div style="
                    width:${r}px;height:${r}px;border-radius:50%;
                    border:2px solid ${col};
                    background:${col}22;
                    box-sizing:border-box;
                    animation:auPulse 2.5s ease-in-out infinite"></div>`,
                iconSize: [r, r], iconAnchor: [r / 2, r / 2],
            }),
            interactive: false,
            zIndexOffset: -10,
        }).addTo(mLayer);

        // Solid centre dot
        const dot = L.circleMarker(coords, {
            radius: Math.round(6 + ratio * 12),
            fillColor: col, color: col,
            weight: 1.5, opacity: 0.9, fillOpacity: 0.7,
        });

        dot.on('click', () => {
            map.flyTo(coords, 7, { animate: true, duration: 0.8 });
        });

        dot.bindPopup(`
            <div style="font-family:monospace;font-size:10px;background:#070b1c;
                color:#c7d4ff;padding:10px;border-radius:6px;min-width:190px;
                line-height:1.8;border:1px solid #1a2d45">
                <div style="font-size:12px;font-weight:700;color:${col};margin-bottom:4px">
                    📍 ${city}
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;font-size:9.5px">
                    <span style="color:#3a5878">Total Threats</span>
                    <span style="color:#fff;font-weight:700">${count.toLocaleString()}</span>
                    <span style="color:#3a5878">Critical</span>
                    <span style="color:#ff3d5a;font-weight:700">${(cityCritCount[city] || 0).toLocaleString()}</span>
                    <span style="color:#3a5878">Max CVSS</span>
                    <span style="color:#ffd740;font-weight:700">${(cityMaxCvss[city] || 0).toFixed(1)}</span>
                    <span style="color:#3a5878">% Critical</span>
                    <span style="color:#ff9800;font-weight:700">${(critPct * 100).toFixed(0)}%</span>
                </div>
            </div>`, { className: 'dark-popup', maxWidth: 220 });

        dot.addTo(mLayer);

        // City label + count
        L.marker([coords[0] - 0.8, coords[1]], {
            icon: L.divIcon({
                className: '',
                html: `<div style="font-family:monospace;font-size:9.5px;font-weight:700;
                    color:${col};white-space:nowrap;text-shadow:0 1px 3px #000">
                    ${city} <span style="color:#fff">${count.toLocaleString()}</span>
                </div>`,
                iconSize: [140, 14], iconAnchor: [70, -4],
            }),
            interactive: false,
        }).addTo(mLayer);
    });

    // Update count label — show ALL threats
    const el = document.getElementById('mapCount');
    if (el) el.textContent =
        `${totalMapped.toLocaleString()} of ${(threats || []).length.toLocaleString()} threats mapped`;

    map.fitBounds(AU_BOUNDS, { padding: [10, 10] });
}

// Pulse animation
(function () {
    const s = document.createElement('style');
    s.textContent = `
        @keyframes auPulse {
            0%,100% { opacity:.7; transform:scale(1); }
            50%      { opacity:.2; transform:scale(1.2); }
        }
        .dark-popup .leaflet-popup-content-wrapper {
            background:transparent!important;border:none!important;
            box-shadow:none!important;padding:0!important;
        }
        .dark-popup .leaflet-popup-content { margin:0!important; }
        .dark-popup .leaflet-popup-tip { background:#1a2d45!important; }
    `;
    document.head.appendChild(s);
})();

document.addEventListener('DOMContentLoaded', initMap);