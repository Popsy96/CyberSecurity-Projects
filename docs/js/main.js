/* ============================================================
   main.js — Core data loading, filtering, stats
   ============================================================ */

window.ALL = [];
window.STATS = {};
window.IR_DATA = {};
window.FILTERED = [];

// ── CHART REGISTRY (prevent duplicate chart errors) ──────────
window.CHARTS = {};
window.mkChart = function (id, type, labels, datasets, extraOpts) {
    const el = document.getElementById(id);
    if (!el) return;
    if (window.CHARTS[id]) { window.CHARTS[id].destroy(); }
    const opts = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: type === 'doughnut' || type === 'pie',
                labels: { color: '#7a9cc8', font: { size: 10 }, boxWidth: 10 },
            },
            tooltip: { callbacks: {} },
        },
        scales: (type === 'doughnut' || type === 'pie') ? {} : {
            x: {
                ticks: { color: '#7a9cc8', font: { size: 9 } },
                grid: { color: '#0f1a35' },
            },
            y: {
                ticks: { color: '#7a9cc8', font: { size: 9 } },
                grid: { color: '#0f1a35' },
            },
        },
        ...extraOpts,
    };
    window.CHARTS[id] = new Chart(el.getContext('2d'), { type, data: { labels, datasets }, options: opts });
};

// ── PALETTE ───────────────────────────────────────────────────
window.PAL = ['#2979ff', '#ff3d5a', '#ff9800', '#ffd740', '#00e5a0', '#9c6bff', '#00d4ff', '#fd7e14'];

// ── COMPUTE STATS ─────────────────────────────────────────────
window.computeStats = (threats) => {
    const total = threats.length;
    const cvssSum = threats.reduce((s, t) => s + (t.cvss_score || 0), 0);

    // Skip empty / Unknown in counts
    const countBy = (key) => {
        const d = {};
        threats.forEach(t => {
            const v = t[key];
            if (!v || v === 'Unknown' || v === 'null' || v === '') return;
            d[v] = (d[v] || 0) + 1;
        });
        return d;
    };

    const nist = { Identify: 0, Protect: 0, Detect: 0, Respond: 0, Recover: 0 };
    threats.forEach(t => { if (nist[t.nist_function] !== undefined) nist[t.nist_function]++; });

    const cvssD = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    threats.forEach(t => { if (cvssD[t.severity] !== undefined) cvssD[t.severity]++; });

    // City — exclude generic AU
    const cityC = {};
    threats.forEach(t => {
        const c = t.city;
        if (!c || c === 'AU' || c === 'Unknown' || c === '') return;
        cityC[c] = (cityC[c] || 0) + 1;
    });

    return {
        total,
        critical: threats.filter(t => t.severity === 'Critical').length,
        high: threats.filter(t => t.severity === 'High').length,
        medium: threats.filter(t => t.severity === 'Medium').length,
        low: threats.filter(t => t.severity === 'Low').length,
        c2: threats.filter(t => t.category === 'C2 Server').length,
        avg_cvss: total ? +(cvssSum / total).toFixed(1) : 0,
        cvss_dist: cvssD,
        nist_dist: nist,
        category_counts: countBy('category'),
        source_counts: window.STATS?.source_counts || countBy('source'),
        city_counts: cityC,
        industry_counts: countBy('industry'),
        malware_type_counts: countBy('malware_type'),
        asd_e8_counts: countBy('asd_e8'),
    };
};

// ── DATE PARSING HELPER ───────────────────────────────────────
// Handles both '22/04/2026 01:45 AEST' and ISO '2026-04-21T15:45' formats
function parseThreatDate(t) {
    // Prefer UTC ISO string — reliable parsing
    if (t.timestamp_utc) return new Date(t.timestamp_utc);
    // Fallback: parse AU format 'DD/MM/YYYY HH:MM AEST'
    if (t.timestamp_au) {
        const m = t.timestamp_au.match(/(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2})/);
        if (m) return new Date(`${m[3]}-${m[2]}-${m[1]}T${m[4]}:${m[5]}:00`);
    }
    return null;
}
// ── DATE FILTER — fixed & redesigned ─────────────────────────
// Tracks which preset is selected without firing until Apply
let _activePreset = 'all';

function getDateRange(preset) {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    switch (preset) {
        case '7days':
            return { from: new Date(today.getTime() - 6 * 86400000), to: new Date(today.getTime() + 86399999) };
        case '30days':
            return { from: new Date(today.getTime() - 29 * 86400000), to: new Date(today.getTime() + 86399999) };
        case 'project':
            // Full CYB815 project period: 13 Apr 2026 → now
            return { from: new Date('2026-04-13T00:00:00'), to: new Date(today.getTime() + 86399999) };
        default: // 'all'
            return null;
    }
}

// Called by preset buttons — applies IMMEDIATELY (no Apply needed)
window.setPreset = function (preset) {
    _activePreset = preset;
    // Highlight correct button
    document.querySelectorAll('.dbtn').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById('btn-' + preset);
    if (btn) btn.classList.add('active');
    // Clear custom inputs when selecting a preset
    const fi = document.getElementById('fromDate');
    const ti = document.getElementById('toDate');
    if (fi) fi.value = '';
    if (ti) ti.value = '';
    // Apply immediately — no need to click Apply for presets
    applyPresetFilter(preset);
};

// Runs the filter for a preset immediately
function applyPresetFilter(preset) {
    const range = getDateRange(preset);
    if (!range) {
        window.FILTERED = [...window.ALL];
    } else {
        window.FILTERED = window.ALL.filter(t => {
            const dt = parseThreatDate(t);
            if (!dt || isNaN(dt)) return true;
            return dt >= range.from && dt <= range.to;
        });
    }
    const info = document.getElementById('dateInfo');
    if (info) {
        const filtered = window.FILTERED.length;
        const total = window.ALL.length;
        info.textContent = filtered === total
            ? `${total.toLocaleString()} threats (all time)`
            : `${filtered.toLocaleString()} of ${total.toLocaleString()} threats`;
    }
    updateAllTabs();
}

// Show how many threats match — updates info label without filtering
function previewDateCount(preset, from, to) {
    let count;
    if (preset === 'all' || (!preset && !from && !to)) {
        count = window.ALL.length;
    } else if (from || to) {
        const f = from || new Date(0);
        const t = to || new Date('2099-12-31');
        count = window.ALL.filter(th => {
            const dt = parseThreatDate(th);
            return !dt || isNaN(dt) || (dt >= f && dt <= t);
        }).length;
    } else {
        const range = getDateRange(preset);
        if (!range) { count = window.ALL.length; }
        else {
            count = window.ALL.filter(th => {
                const dt = parseThreatDate(th);
                return !dt || isNaN(dt) || (dt >= range.from && dt <= range.to);
            }).length;
        }
    }
    const info = document.getElementById('dateInfo');
    if (info) {
        if (count === window.ALL.length) {
            info.textContent = '';
        } else {
            info.textContent = `${count.toLocaleString()} threats match`;
        }
    }
}

// Apply button — only needed for custom date range
window.applyActiveDateFilter = function () {
    const fromVal = document.getElementById('fromDate')?.value;
    const toVal = document.getElementById('toDate')?.value;

    if (!fromVal && !toVal) {
        // No custom dates — just run the active preset
        applyPresetFilter(_activePreset);
        return;
    }

    // Custom range
    const from = fromVal ? new Date(fromVal) : new Date(0);
    const to = toVal ? new Date(toVal + 'T23:59:59') : new Date('2099-12-31');
    window.FILTERED = window.ALL.filter(t => {
        const dt = parseThreatDate(t);
        if (!dt || isNaN(dt)) return true;
        return dt >= from && dt <= to;
    });

    // Clear preset highlight — custom range is active
    document.querySelectorAll('.dbtn').forEach(b => b.classList.remove('active'));
    _activePreset = 'custom';

    const info = document.getElementById('dateInfo');
    if (info) {
        const filtered = window.FILTERED.length;
        const total = window.ALL.length;
        info.textContent = filtered === total
            ? ''
            : `${filtered.toLocaleString()} of ${total.toLocaleString()} threats`;
    }
    updateAllTabs();
};

// Legacy — kept so any existing onclick="applyDateFilter(...)" still works
window.applyDateFilter = function (preset) {
    window.setPreset(preset);
    window.applyActiveDateFilter();
};

window.clearDateFilter = function () {
    _activePreset = 'all';
    document.querySelectorAll('.dbtn').forEach(b => b.classList.remove('active'));
    document.getElementById('btn-all')?.classList.add('active');
    const fi = document.getElementById('fromDate');
    const ti = document.getElementById('toDate');
    if (fi) fi.value = '';
    if (ti) ti.value = '';
    // Reset FILTERED to full dataset
    window.FILTERED = [...window.ALL];
    const info = document.getElementById('dateInfo');
    if (info) info.textContent = `${window.ALL.length.toLocaleString()} threats (all time)`;
    updateAllTabs();
};

// ── FEED FILTERS ──────────────────────────────────────────────
// ── FEED FILTER STATE ─────────────────────────────────────────
let _feedSev = '';  // active severity pill

// ── APPLY FEED FILTERS ────────────────────────────────────────
window.applyFeedFilters = function () {
    const search = (document.getElementById('feedSearch')?.value || '').toLowerCase().trim();
    const sevF = _feedSev;
    const catF = document.getElementById('catFilter')?.value || '';
    const typeF = document.getElementById('typeFilter')?.value || '';
    const cityF = document.getElementById('cityFilter')?.value || '';
    const nistF = document.getElementById('nistFilter')?.value || '';
    const srcF = document.getElementById('srcFilter')?.value || '';
    const malwareF = document.getElementById('malwareFilter')?.value || '';
    const mitreF = document.getElementById('mitreFilter')?.value || '';

    // Always filter from the date-filtered base
    const base = window.FILTERED || window.ALL;

    const result = base.filter(t => {
        // Free text search across key fields
        if (search) {
            const hay = [
                t.ioc, t.category, t.type, t.source,
                t.city, t.mitre_technique, t.nist_function,
                t.industry, t.malware_family, t.severity
            ].map(v => (v || '').toLowerCase()).join(' ');
            if (!hay.includes(search)) return false;
        }
        if (sevF && t.severity !== sevF) return false;
        if (catF && t.category !== catF) return false;
        if (typeF && t.type !== typeF) return false;
        if (cityF && t.city !== cityF) return false;
        if (nistF && t.nist_function !== nistF) return false;
        if (srcF && t.source !== srcF) return false;
        if (malwareF && t.malware_type !== malwareF) return false;
        if (mitreF && t.mitre_technique !== mitreF) return false;
        return true;
    });

    renderTable(result);

    // Update count
    const el = document.getElementById('filterCount');
    if (el) el.textContent =
        result.length === window.ALL.length
            ? `Showing all ${window.ALL.length.toLocaleString()} threats`
            : `Showing ${result.length.toLocaleString()} of ${window.ALL.length.toLocaleString()} threats`;

    // Show active filter badges
    renderActiveBadges(search, sevF, catF, typeF, cityF, nistF, srcF, malwareF, mitreF);
};

function renderActiveBadges(search, sev, cat, type, city, nist, src, mal, mitre) {
    const el = document.getElementById('activeFilterBadges');
    if (!el) return;
    const active = [];
    if (search) active.push({ label: `"${search}"`, clear: () => { document.getElementById('feedSearch').value = ''; } });
    if (sev) active.push({ label: `Sev: ${sev}`, clear: () => setSevPill('') });
    if (cat) active.push({ label: `Cat: ${cat}`, clear: () => { document.getElementById('catFilter').value = ''; } });
    if (type) active.push({ label: `Type: ${type}`, clear: () => { document.getElementById('typeFilter').value = ''; } });
    if (city) active.push({ label: `City: ${city}`, clear: () => { document.getElementById('cityFilter').value = ''; } });
    if (nist) active.push({ label: `NIST: ${nist}`, clear: () => { document.getElementById('nistFilter').value = ''; } });
    if (src) active.push({ label: `Src: ${src}`, clear: () => { document.getElementById('srcFilter').value = ''; } });
    if (mal) active.push({ label: `Mal: ${mal}`, clear: () => { document.getElementById('malwareFilter').value = ''; } });

    el.innerHTML = active.map((a, i) =>
        `<span class="factive-badge" onclick="clearOneBadge(${i})">✕ ${a.label}</span>`
    ).join('');
    el._clearFns = active.map(a => a.clear);
}

window.clearOneBadge = function (i) {
    const el = document.getElementById('activeFilterBadges');
    if (el?._clearFns?.[i]) { el._clearFns[i](); window.applyFeedFilters(); }
};

// Severity pill toggle
function setSevPill(sev) {
    _feedSev = sev;
    document.querySelectorAll('.fsev-pill').forEach(p => {
        p.classList.toggle('active', p.dataset.sev === sev);
    });
}

window.clearFeedFilters = function () {
    document.getElementById('feedSearch').value = '';
    setSevPill('');
    ['catFilter', 'typeFilter', 'cityFilter', 'srcFilter', 'nistFilter', 'malwareFilter', 'mitreFilter']
        .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
    // Clear quick-category pills
    document.querySelectorAll('.fquick-pill').forEach(p => p.classList.remove('active'));
    const result = window.FILTERED || window.ALL;
    renderTable(result);
    const el = document.getElementById('filterCount');
    if (el) el.textContent = `Showing all ${result.length.toLocaleString()} threats`;
    const badges = document.getElementById('activeFilterBadges');
    if (badges) badges.innerHTML = '';
};

// ── UPDATE ALL TABS ───────────────────────────────────────────
function updateAllTabs() {
    // Always use FILTERED — it equals ALL when no filter is active
    const t = window.FILTERED || window.ALL;
    renderOverview(t);
    renderTimeline(t);
    renderTable(t);
    renderAnalytics(t);
    renderRisk(t);
    const el = document.getElementById('filterCount');
    if (el) el.textContent = `Showing ${t.length.toLocaleString()} of ${window.ALL.length.toLocaleString()} threats`;
}

// ── SIDEBAR FEED STATUS ───────────────────────────────────────
function renderSidebarFeeds() {
    const sc = window.STATS.source_counts || {};
    const feeds = ['AlienVault OTX', 'AbuseIPDB', 'URLhaus', 'Feodo Tracker'];
    const el = document.getElementById('sidebarFeeds');
    if (!el) return;
    el.innerHTML = feeds.map(f => {
        const c = sc[f] || 0, on = c > 0;
        return `<div style="display:flex;align-items:center;gap:6px;padding:6px 10px;font-size:11px">
      <span style="width:7px;height:7px;border-radius:50%;flex-shrink:0;
        background:${on ? '#00e5a0' : '#3a5878'};
        ${on ? 'box-shadow:0 0 5px #00e5a0' : ''}"></span>
      <span style="flex:1;color:${on ? '#cde0ff' : '#3a5878'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${f}</span>
      <span style="font-size:10px;color:${on ? '#7a9cc8' : '#3a5878'}">${c.toLocaleString()}</span>
    </div>`;
    }).join('');
}

// ── CLOCK ────────────────────────────────────────────────────
function tick() {
    const now = new Date();
    const off = [10, 11, 12, 1, 2, 3].includes(now.getUTCMonth() + 1) ? 11 : 10;
    const au = new Date(now.getTime() + off * 3600000);
    const lbl = off === 11 ? 'AEDT' : 'AEST';
    const cl = document.getElementById('auClock');
    const cu = document.getElementById('utcClock');
    if (cl) cl.textContent = `AU ${au.toISOString().replace('T', ' ').substring(0, 19)} ${lbl}`;
    if (cu) cu.textContent = now.toUTCString().replace('GMT', 'UTC');
}
setInterval(tick, 1000); tick();

// ── LOAD DATA ─────────────────────────────────────────────────
function loadData() {
    // Show loading state
    const kpis = ['kpiTotal', 'kpiCritical', 'kpiHigh', 'kpiCvss', 'kpiPhishing', 'kpiSuspicious'];
    kpis.forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '...'; });

    const paths = ['data.json', '../data.json'];
    let idx = 0;

    function tryNext() {
        if (idx >= paths.length) { showError(); return; }
        const path = paths[idx++];
        const xhr = new XMLHttpRequest();
        xhr.open('GET', path + '?t=' + Date.now(), true);
        xhr.onload = function () {
            if (xhr.status === 0 || xhr.status === 200) {
                try {
                    const data = JSON.parse(xhr.responseText);
                    window.ALL = data.threats || [];
                    window.STATS = data.stats || {};
                    window.IR_DATA = data.ir_data || {};
                    window.FILTERED = [...window.ALL];

                    const lu = document.getElementById('lastUpdated');
                    if (lu) lu.textContent = `Updated: ${window.STATS.last_updated || '—'}`;

                    document.getElementById('btn-all')?.classList.add('active');

                    // Render KPIs and charts immediately
                    renderOverview(window.ALL);
                    renderSidebarFeeds();
                    renderFetchRuns();
                    renderTimeline(window.ALL);

                    // Defer heavier renders slightly so UI stays responsive
                    setTimeout(() => {
                        renderAnalytics(window.ALL);
                        renderRisk(window.ALL);
                        renderTable(window.ALL);
                        initIR(window.IR_DATA);
                        const el = document.getElementById('filterCount');
                        if (el) el.textContent = `Showing ${window.ALL.length.toLocaleString()} of ${window.ALL.length.toLocaleString()} threats`;
                    }, 50);

                    console.log(`✅ Loaded ${window.ALL.length.toLocaleString()} threats from ${path}`);
                } catch (e) {
                    console.error('JSON parse error:', e);
                    tryNext();
                }
            } else {
                tryNext();
            }
        };
        xhr.onerror = tryNext;
        xhr.send();
    }
    tryNext();
}

function showError() {
    console.error('❌ data.json not found');
    const b = document.getElementById('iocBody');
    if (b) b.innerHTML = `
    <tr><td colspan="12" style="text-align:center;color:#ff9800;padding:30px;font-size:13px">
      data.json not found — Run: <code style="color:#00e5a0">python main.py</code> then refresh this page
    </td></tr>`;
    // Still show tabs
    document.querySelectorAll('.nav-item').forEach(n => n.style.pointerEvents = 'auto');
}



// clearDateFilter is defined above — no reassignment needed

// ── BADGE HELPERS — canonical definitions ─────────────────────
window.sevBadge = (s) => {
    const m = { Critical: 'bdg bc', High: 'bdg bh', Medium: 'bdg bm', Low: 'bdg bl' };
    return `<span class="${m[s] || 'bdg bl'}">${s || '—'}</span>`;
};
window.nistBadge = (n) => {
    return n ? `<span class="bdg bn-${n}" style="font-size:9.5px">${n}</span>`
        : '<span style="color:#304860;font-size:10px">—</span>';
};
window.mitreBadge = (t) => {
    return t ? `<span class="bdg bmt">${t}</span>`
        : '<span style="color:#304860;font-size:10px">—</span>';
};
window.cvssColor = (v) => v >= 9 ? '#ff4545' : v >= 7 ? '#ff8c00' : v >= 4 ? '#ffc800' : '#00d68f';
// ── SINGLE INIT ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

    // ── Apply / Clear buttons ──
    document.getElementById('applyFiltersBtn')
        ?.addEventListener('click', window.applyFeedFilters);
    document.getElementById('clearFilters')
        ?.addEventListener('click', window.clearFeedFilters);

    // ── Search bar — apply on Enter or after 400ms pause ──
    const searchEl = document.getElementById('feedSearch');
    let searchTimer = null;
    if (searchEl) {
        searchEl.addEventListener('input', () => {
            clearTimeout(searchTimer);
            // Show live count immediately without full re-render
            const q = searchEl.value.toLowerCase().trim();
            if (q.length > 0) {
                const base = window.FILTERED || window.ALL;
                const n = base.filter(t => [
                    t.ioc, t.category, t.type, t.source,
                    t.city, t.mitre_technique, t.severity
                ].some(v => (v || '').toLowerCase().includes(q))).length;
                const el = document.getElementById('filterCount');
                if (el) el.textContent = `${n.toLocaleString()} threats match`;
            }
            searchTimer = setTimeout(window.applyFeedFilters, 400);
            const clr = document.getElementById('feedSearchClear');
            if (clr) clr.style.display = searchEl.value ? 'block' : 'none';
        });
        searchEl.addEventListener('keydown', e => {
            if (e.key === 'Enter') { clearTimeout(searchTimer); window.applyFeedFilters(); }
        });
    }
    document.getElementById('feedSearchClear')?.addEventListener('click', () => {
        document.getElementById('feedSearch').value = '';
        document.getElementById('feedSearchClear').style.display = 'none';
        window.applyFeedFilters();
    });

    // ── Severity pills ──
    document.querySelectorAll('.fsev-pill').forEach(pill => {
        pill.addEventListener('click', () => {
            setSevPill(pill.dataset.sev);
            window.applyFeedFilters();
        });
    });

    // ── Quick category pills ──
    document.querySelectorAll('.fquick-pill').forEach(pill => {
        pill.addEventListener('click', () => {
            const isActive = pill.classList.contains('active');
            document.querySelectorAll('.fquick-pill').forEach(p => p.classList.remove('active'));
            const catSel = document.getElementById('catFilter');
            if (isActive) {
                // Toggle off
                if (catSel) catSel.value = '';
            } else {
                pill.classList.add('active');
                if (catSel) catSel.value = pill.dataset.cat;
            }
            window.applyFeedFilters();
        });
    });

    // ── Advanced dropdowns — highlight when active ──
    ['catFilter', 'typeFilter', 'cityFilter', 'srcFilter', 'nistFilter', 'malwareFilter', 'mitreFilter']
        .forEach(id => {
            document.getElementById(id)?.addEventListener('change', function () {
                this.classList.toggle('active-filter', this.value !== '');
                // Sync quick pills with category dropdown
                if (id === 'catFilter') {
                    document.querySelectorAll('.fquick-pill').forEach(p => {
                        p.classList.toggle('active', p.dataset.cat === this.value);
                    });
                }
            });
        });

    // ── Custom date inputs ──
    const fd = document.getElementById('fromDate');
    const td = document.getElementById('toDate');
    const onCustomChange = () => {
        document.querySelectorAll('.dbtn').forEach(b => b.classList.remove('active'));
        _activePreset = 'custom';
        const info = document.getElementById('dateInfo');
        if (info) info.textContent = 'Set both dates then click Apply Custom';
    };
    if (fd) fd.addEventListener('change', onCustomChange);
    if (td) td.addEventListener('change', onCustomChange);

    // ── Load data ──
    loadData();
});