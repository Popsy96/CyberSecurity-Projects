/* ============================================================
   map.js — Leaflet.js Australia threat map
   Fixed to AU bounds — no zoom needed
   ============================================================ */

let map, mLayer;

// Australia geographic bounds
const AU_BOUNDS = L.latLngBounds(
    L.latLng(-44.0, 112.0),  // SW corner
    L.latLng(-9.5, 154.5)   // NE corner
);

function initMap() {
    map = L.map('auMap', {
        center: [-27.0, 133.5],   // Centre of Australia
        zoom: 4,
        minZoom: 4,               // Can't zoom out past Australia view
        maxZoom: 10,              // Reasonable city-level zoom
        maxBounds: AU_BOUNDS,     // Locked to AU — can't pan away
        maxBoundsViscosity: 1.0,  // Hard lock — no bounce past bounds
        zoomControl: true,
        attributionControl: false,
    });

    // Dark-tinted tile layer
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 18,
        opacity: 0.30,
    }).addTo(map);

    // Add AU state boundary overlay for context
    addStateLabels();

    mLayer = L.layerGroup().addTo(map);

    // Expose map globally so showTab can call invalidateSize()
    window.map = map;
}

// ── State label markers ───────────────────────────────────────
function addStateLabels() {
    const states = [
        { name: 'WA', lat: -25.5, lng: 121.6 },
        { name: 'NT', lat: -19.5, lng: 133.5 },
        { name: 'SA', lat: -30.0, lng: 135.5 },
        { name: 'QLD', lat: -22.5, lng: 144.5 },
        { name: 'NSW', lat: -32.5, lng: 146.5 },
        { name: 'VIC', lat: -37.0, lng: 144.8 },
        { name: 'TAS', lat: -42.0, lng: 146.5 },
        { name: 'ACT', lat: -35.5, lng: 149.1 },
    ];
    states.forEach(s => {
        L.marker([s.lat, s.lng], {
            icon: L.divIcon({
                className: '',
                html: `<div style="
                    font-family:'Inter',monospace;font-size:9px;font-weight:700;
                    color:rgba(120,160,200,0.45);letter-spacing:1.5px;
                    pointer-events:none;white-space:nowrap;user-select:none">
                    ${s.name}
                </div>`,
                iconSize: [30, 14],
                iconAnchor: [15, 7],
            }),
            interactive: false,
        }).addTo(map);
    });
}

// ── City coordinates lookup ───────────────────────────────────
const CITY_COORDS = {
    'Perth': { lat: -31.9505, lng: 115.8605 },
    'Darwin': { lat: -12.4634, lng: 130.8456 },
    'Adelaide': { lat: -34.9285, lng: 138.6007 },
    'Brisbane': { lat: -27.4698, lng: 153.0251 },
    'Sydney': { lat: -33.8688, lng: 151.2093 },
    'Melbourne': { lat: -37.8136, lng: 144.9631 },
    'Hobart': { lat: -42.8821, lng: 147.3272 },
    'Canberra': { lat: -35.2809, lng: 149.1300 },
    'Gold Coast': { lat: -28.0167, lng: 153.4000 },
    'Newcastle': { lat: -32.9267, lng: 151.7789 },
};

// ── Render threat markers ─────────────────────────────────────
function renderMap(threats) {
    if (!map) return;
    mLayer.clearLayers();
    let n = 0;

    // Group threats by city for cluster sizing
    const cityGroups = {};
    (threats || []).forEach(t => {
        const city = t.city;
        if (!city || city === 'AU' || city === 'Unknown') return;
        if (!cityGroups[city]) cityGroups[city] = [];
        cityGroups[city].push(t);
    });

    // Plot individual markers (up to 1500 for performance)
    const sample = (threats || []).filter(t => t.lat && t.lng).slice(0, 1500);

    sample.forEach(t => {
        const c = cvssColor(t.cvss_score || 0);
        const r = t.severity === 'Critical' ? 8 : t.severity === 'High' ? 7 : 5;

        const icon = L.divIcon({
            className: '',
            html: `<div style="
                width:${r * 2}px;height:${r * 2}px;border-radius:50%;
                background:${c};opacity:0.85;
                box-shadow:0 0 ${r + 3}px ${c},0 0 ${r * 2 + 4}px ${c}44;
                border:1px solid ${c}99"></div>`,
            iconSize: [r * 2, r * 2],
            iconAnchor: [r, r],
        });

        const m = L.marker([t.lat, t.lng], { icon });
        m.bindPopup(`
            <div style="font-family:monospace;font-size:10px;background:#070b1c;color:#c7d4ff;
                        padding:10px;border-radius:6px;min-width:210px;line-height:1.8;
                        border:1px solid #1a2d45">
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <b style="color:${c};font-size:11px">${t.severity}</b>
                    <b style="color:${c}">CVSS ${(t.cvss_score || 0).toFixed(1)}</b>
                </div>
                <div style="color:#7fc4ff;margin-bottom:3px;word-break:break-all">
                    ${(t.ioc || '').substring(0, 44)}${(t.ioc || '').length > 44 ? '…' : ''}
                </div>
                <div style="color:#4a9080">${t.category || '—'}</div>
                <div style="margin-top:4px;padding-top:4px;border-top:1px solid #1a2d45;
                    display:grid;grid-template-columns:1fr 1fr;gap:2px;font-size:9.5px">
                    <span>⚔ ${t.mitre_technique || '—'}</span>
                    <span>🏛 ${t.nist_function || '—'}</span>
                    <span>🛡 ${(t.asd_e8 || '—').split('·')[0].trim()}</span>
                    <span>📍 ${t.city || 'AU'}</span>
                </div>
                <div style="margin-top:4px;font-size:9px;color:#304860">${t.source || '—'}</div>
            </div>`, { className: 'dark-popup', maxWidth: 260 });

        mLayer.addLayer(m);
        n++;
    });

    // Add city pulse rings for cities with many threats
    Object.entries(cityGroups).forEach(([city, group]) => {
        const coords = CITY_COORDS[city];
        if (!coords || group.length < 50) return;

        const size = Math.min(20 + Math.floor(group.length / 100) * 4, 42);
        const critCount = group.filter(t => t.severity === 'Critical').length;
        const col = critCount > group.length * 0.5 ? '#ff4545' : '#ff8c00';

        L.marker([coords.lat, coords.lng], {
            icon: L.divIcon({
                className: '',
                html: `<div style="
                    width:${size}px;height:${size}px;border-radius:50%;
                    border:2px solid ${col};
                    background:${col}18;
                    animation:pulse 2s ease-in-out infinite;
                    box-sizing:border-box"></div>`,
                iconSize: [size, size],
                iconAnchor: [size / 2, size / 2],
            }),
            interactive: false,
            zIndexOffset: -100,
        }).addTo(mLayer);

        // City label with count
        L.marker([coords.lat, coords.lng - 0.5], {
            icon: L.divIcon({
                className: '',
                html: `<div style="
                    font-family:monospace;font-size:9px;font-weight:700;
                    color:${col};white-space:nowrap;
                    text-shadow:0 0 4px #000">
                    ${city} <span style="color:#fff">${group.length.toLocaleString()}</span>
                </div>`,
                iconSize: [120, 14],
                iconAnchor: [60, -10],
            }),
            interactive: false,
        }).addTo(mLayer);
    });

    const el = document.getElementById('mapCount');
    if (el) el.textContent = `${n.toLocaleString()} threats plotted across Australia`;

    // Fit map to AU bounds on first render
    map.fitBounds(AU_BOUNDS, { padding: [10, 10] });
}

// ── Pulse animation ───────────────────────────────────────────
(function addPulseStyle() {
    const style = document.createElement('style');
    style.textContent = `
        @keyframes pulse {
            0%,100% { opacity:0.8; transform:scale(1); }
            50% { opacity:0.3; transform:scale(1.15); }
        }
        .dark-popup .leaflet-popup-content-wrapper {
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0 !important;
        }
        .dark-popup .leaflet-popup-content { margin: 0 !important; }
        .dark-popup .leaflet-popup-tip { background: #1a2d45 !important; }
    `;
    document.head.appendChild(style);
})();

// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', initMap);