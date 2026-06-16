/* ============================================================
   charts.js — Redesigned dashboard charts
   CYB815 Group 14 — Clean, no repetition, all visible
   ============================================================ */

// ── OVERVIEW ─────────────────────────────────────────────────
function renderOverview(threats) {
    const s = computeStats(threats);
    const isFiltered = threats.length < window.ALL.length;

    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = typeof val === 'number' ? val.toLocaleString() : val;
    };

    // KPI cards — always use filtered threats so date filter reflects here
    // Only fall back to STATS for total_in_db (full DB count) when unfiltered
    set('kpiTotal', isFiltered
        ? threats.length.toLocaleString()
        : (window.STATS.total_in_db || s.total).toLocaleString());
    set('kpiCritical', s.critical.toLocaleString());
    set('kpiHigh', s.high.toLocaleString());
    set('kpiCvss', s.avg_cvss.toFixed(1));
    set('kpiPhishing', (s.category_counts['Phishing'] || 0).toLocaleString());

    // Suspicious = brute force + SSH brute + suspicious + port scan
    const suspicious =
        (s.category_counts['Brute Force'] || 0) +
        (s.category_counts['SSH Brute Force'] || 0) +
        (s.category_counts['Suspicious Activity'] || 0) +
        (s.category_counts['Port Scan'] || 0);
    set('kpiSuspicious', suspicious.toLocaleString());

    // Project brief coverage badges
    renderBriefCoverage(s);

    // Attack categories — exclude C2 dominance, show project brief focus
    const cats = s.category_counts;
    const briefCats = [
        'Phishing',
        'Malware Distribution',
        'Brute Force',
        'SSH Brute Force',
        'C2 Server',
        'Web App Attack',
        'CVE',
        'Fraud Orders',
        'DDoS Attack',
    ];
    const catData = briefCats
        .map(k => ({ label: k, val: cats[k] || 0 }))
        .filter(x => x.val > 0)
        .sort((a, b) => b.val - a.val);

    mkChart('ovCatChart', 'bar',
        catData.map(x => x.label),
        [{
            label: 'Threats',
            data: catData.map(x => x.val),
            backgroundColor: ['#ff3d5a', '#ff9800', '#ffd740', '#00e5a0',
                '#2979ff', '#9c6bff', '#00d4ff', '#fd7e14', '#e91e63'],
            borderWidth: 0, borderRadius: 4,
        }],
        { indexAxis: 'y' }
    );

    renderMap(threats);
    renderFeedStatusGraph();
    renderSevBars(threats);
    renderAdditionalCats(s);
}

// ── PROJECT BRIEF COVERAGE ─────────────────────────────────
function renderBriefCoverage(s) {
    const el = document.getElementById('briefCoverage');
    if (!el) return;
    const items = [
        {
            label: 'Malware Outbreaks',
            count: s.category_counts['Malware Distribution'] || 0,
            color: '#ff3d5a',
        },
        {
            label: 'Phishing Campaigns',
            count: s.category_counts['Phishing'] || 0,
            color: '#ff9800',
        },
        {
            label: 'Suspicious Network Activity',
            count: (s.category_counts['Brute Force'] || 0) +
                (s.category_counts['SSH Brute Force'] || 0) +
                (s.category_counts['Suspicious Activity'] || 0),
            color: '#ffd740',
        },
    ];
    el.innerHTML = items.map(i => `
    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:13px;color:var(--green);font-weight:700">✓</span>
      <span style="flex:1;font-size:12px;color:var(--text);font-weight:600">${i.label}</span>
      <span style="font-size:13px;font-weight:800;color:${i.color}">${i.count.toLocaleString()}</span>
    </div>`).join('');
}

// ── PROJECT BRIEF — TOPBAR PILLS ─────────────────────────────
function renderBriefTopbar(s) {
    const el = document.getElementById('briefTopbar');
    if (!el) return;
    const items = [
        { label: 'Malware', count: s.category_counts['Malware Distribution'] || 0, col: '#ff3d5a', border: 'rgba(255,61,90,.3)' },
        { label: 'Phishing', count: s.category_counts['Phishing'] || 0, col: '#ff9800', border: 'rgba(255,152,0,.3)' },
        { label: 'Suspicious', count: (s.category_counts['Brute Force'] || 0) + (s.category_counts['SSH Brute Force'] || 0) + (s.category_counts['Suspicious Activity'] || 0), col: '#ffd740', border: 'rgba(255,215,64,.3)' },
    ];
    el.innerHTML = items.map(i => `
        <div class="brief-pill" style="color:${i.col};border-color:${i.border};background:${i.col}11">
            <span style="font-size:11px">✓</span>
            ${i.label}: <b>${i.count.toLocaleString()}</b>
        </div>`).join('');
}

// ── SEVERITY BARS ─────────────────────────────────────────────
function renderSevBars(threats) {
    const total = Math.max(threats.length, 1);
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    threats.forEach(t => { if (counts[t.severity] !== undefined) counts[t.severity]++; });
    const el = document.getElementById('sevBars');
    if (!el) return;
    el.innerHTML = [
        { l: 'Critical', col: '#ff3d5a' },
        { l: 'High', col: '#ff9800' },
        { l: 'Medium', col: '#ffd740' },
        { l: 'Low', col: '#00e5a0' },
    ].map(i => `
    <div class="sev-bar-row">
      <div class="sev-bar-top">
        <span style="font-size:12px;color:${i.col};font-weight:600">${i.l}</span>
        <span style="font-size:12px;color:#ffffff;font-weight:700">${(counts[i.l] || 0).toLocaleString()}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${((counts[i.l] || 0) / total) * 100}%;background:${i.col}"></div>
      </div>
    </div>`).join('');
}

// ── FEED STATUS GRAPH ────────────────────────────────────────
function renderFeedStatusGraph() {
    const el = document.getElementById('feedStatusGraph');
    if (!el) return;
    const sc = window.STATS.source_counts || {};
    const feeds = [
        { name: 'AlienVault OTX', col: '#2979ff', icon: 'OTX' },
        { name: 'AbuseIPDB', col: '#ff3d5a', icon: 'ABI' },
        { name: 'URLhaus', col: '#ff9800', icon: 'URL' },
        { name: 'Feodo Tracker', col: '#9c6bff', icon: 'FDO' },
    ];
    const max = Math.max(...feeds.map(f => sc[f.name] || 0), 1);
    el.innerHTML = feeds.map(f => {
        const c = sc[f.name] || 0;
        const on = c > 0;
        const pct = (c / max) * 100;
        return `
      <div style="margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <div style="display:flex;align-items:center;gap:7px">
            <span style="width:8px;height:8px;border-radius:50%;flex-shrink:0;
              background:${on ? f.col : '#3a5878'};
              ${on ? 'box-shadow:0 0 6px ' + f.col : ''}"></span>
            <span style="font-size:11.5px;color:${on ? '#cde0ff' : '#3a5878'};font-weight:500">${f.name}</span>
          </div>
          <span style="font-size:12px;font-weight:800;color:${on ? f.col : '#3a5878'}">${c.toLocaleString()}</span>
        </div>
        <div style="height:5px;background:#0f1a35;border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:${f.col};border-radius:3px;transition:width .8s ease"></div>
        </div>
      </div>`;
    }).join('');
}

// ── TIMELINE ─────────────────────────────────────────────────
function renderTimeline() {
    const tl = window.STATS.timeline || [];
    if (!tl.length) return;

    // Always start from 13 April 2026 as per project start date
    const START_DATE = '2026-04-13';
    const withData = tl.filter(r => r.count > 0);
    if (!withData.length) return;
    const lastDate = withData[withData.length - 1].date;
    const filtered = tl.filter(r => r.date >= START_DATE && r.date <= lastDate);

    const labels = filtered.map(r => r.date);
    const values = filtered.map(r => r.count);

    mkChart('timelineChart', 'line', labels,
        [{
            label: 'IOC Detections',
            data: values,
            borderColor: '#0066ff',
            backgroundColor: 'rgba(0,102,255,.1)',
            fill: true,
            tension: .4,
            pointRadius: (ctx) => ctx.raw > 0 ? 4 : 2,
            pointBackgroundColor: (ctx) => ctx.raw > 0 ? '#0066ff' : '#112240',
            pointBorderColor: '#fff',
            pointBorderWidth: 1.5,
        }],
        {
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: ctx => ` ${ctx.parsed.y.toLocaleString()} threats`
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        maxTicksLimit: 15,
                        color: '#7a9fc0',
                        font: { size: 9 }
                    },
                    grid: { color: '#0a1628' }
                },
                y: {
                    ticks: { color: '#7a9fc0', font: { size: 9 } },
                    grid: { color: '#0a1628' }
                }
            }
        }
    );
}

// ── FETCH RUNS ────────────────────────────────────────────────
function renderFetchRuns() {
    const runs = window.STATS.fetch_runs || [];
    const el = document.getElementById('fetchRuns');
    if (!el) return;
    if (!runs.length) {
        el.innerHTML = '<div style="color:#3a5878;font-size:11px;padding:8px 0">No run history yet.</div>';
        return;
    }
    el.innerHTML = runs.slice(0, 5).map(r => `
    <div style="display:flex;align-items:center;justify-content:space-between;
      padding:7px 0;border-bottom:1px solid #0f1a35">
      <span style="color:#7a9cc8;font-size:11px">${r.run_time_au || '—'}</span>
      <div style="display:flex;gap:5px;align-items:center">
        <span class="badge badge-critical">${r.critical || 0}</span>
        <span class="badge badge-high">${r.high || 0}</span>
        <span style="font-size:10px;color:#00e5a0;font-weight:700">+${r.new_threats || 0}</span>
      </div>
    </div>`).join('');
}


// u2500u2500 FEED STATUS u2014 alias kept for backward compatibility u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500
// renderSidebarFeeds() in main.js is the canonical version.
// This stub prevents ReferenceError if called from loadData().
function renderFeedStatus() { if (typeof renderSidebarFeeds === "function") renderSidebarFeeds(); }

// ── ANALYTICS ─────────────────────────────────────────────────
function renderAnalytics(threats) {
    const s = computeStats(threats);
    // Prefer pre-computed stats when showing all data (more accurate — includes full DB)
    const useStats = (!window.FILTERED || window.FILTERED.length === window.ALL.length);
    const cityCounts = useStats ? (window.STATS.city_counts || s.city_counts) : s.city_counts;
    const indCounts = useStats ? (window.STATS.industry_counts || s.industry_counts) : s.industry_counts;
    const malTypeCounts = useStats ? (window.STATS.malware_type_counts || s.malware_type_counts) : s.malware_type_counts;
    const asdCounts = useStats ? (window.STATS.asd_e8_counts || s.asd_e8_counts) : s.asd_e8_counts;

    // NIST cards
    const nd = s.nist_dist;
    const set = (id, v) => {
        const el = document.getElementById(id);
        if (el) el.textContent = (v || 0).toLocaleString();
    };
    set('nistId', nd.Identify || 0);
    set('nistPr', nd.Protect || 0);
    set('nistDe', nd.Detect || 0);
    set('nistRe', nd.Respond || 0);
    set('nistRc', nd.Recover || 0);

    // Cities — sorted, exclude AU/Unknown
    const topCities = Object.entries(cityCounts)
        .sort((a, b) => b[1] - a[1]).slice(0, 8);
    mkChart('cityChart', 'bar',
        topCities.map(x => x[0]),
        [{
            label: 'Threats', data: topCities.map(x => x[1]),
            backgroundColor: '#00d4ff', borderWidth: 0, borderRadius: 3
        }]
    );

    // Industries — exclude Other, sorted
    const indFiltered = Object.entries(indCounts)
        .filter(([k]) => k !== 'Other' && k !== 'Unknown')
        .sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (indFiltered.length) {
        mkChart('indChart', 'bar',
            indFiltered.map(x => x[0]),
            [{
                label: 'Threats', data: indFiltered.map(x => x[1]),
                backgroundColor: '#ff9800', borderWidth: 0, borderRadius: 3
            }],
            { indexAxis: 'y' }
        );
    }

    // Malware types — exclude Unknown
    const mt = malTypeCounts;
    const mtClean = Object.fromEntries(
        Object.entries(mt).filter(([k, v]) => k !== 'Unknown' && v > 0)
    );
    if (Object.keys(mtClean).length) {
        mkChart('malwareTypeChart', 'doughnut',
            Object.keys(mtClean),
            [{
                data: Object.values(mtClean),
                backgroundColor: ['#ff3d5a', '#ff9800', '#ffd740', '#2979ff', '#9c6bff'],
                borderColor: '#060b18', borderWidth: 3
            }]
        );
    }

    // ASD E8 — sorted horizontal
    const topAsd = Object.entries(asdCounts)
        .filter(([k]) => k && k !== 'Unknown')
        .sort((a, b) => b[1] - a[1]).slice(0, 7);
    mkChart('asdChart', 'bar',
        topAsd.map(x => x[0]),
        [{
            label: 'Threats', data: topAsd.map(x => x[1]),
            backgroundColor: '#00e5a0', borderWidth: 0, borderRadius: 3
        }],
        { indexAxis: 'y' }
    );

    // AU States
    const cmap = {
        Sydney: 'NSW', Newcastle: 'NSW', Melbourne: 'VIC',
        Brisbane: 'QLD', 'Gold Coast': 'QLD', Perth: 'WA',
        Adelaide: 'SA', Hobart: 'TAS', Canberra: 'ACT', Darwin: 'NT'
    };
    const stateAgg = { NSW: 0, VIC: 0, QLD: 0, WA: 0, SA: 0, TAS: 0, ACT: 0, NT: 0 };
    Object.entries(cityCounts).forEach(([city, count]) => {
        if (cmap[city]) stateAgg[cmap[city]] += count;
    });
    const sortedStates = Object.entries(stateAgg)
        .filter(([, v]) => v > 0)
        .sort((a, b) => b[1] - a[1]);
    mkChart('stateChart', 'bar',
        sortedStates.map(x => x[0]),
        [{
            label: 'Threats', data: sortedStates.map(x => x[1]),
            backgroundColor: '#2979ff', borderWidth: 0, borderRadius: 3
        }]
    );

    // IOC Types
    renderIocTypes(threats);

    // Top malware families
    const mfCounts = {};
    threats.forEach(t => {
        const f = t.malware_family;
        if (f && f.length > 1 && f.length < 30 && f.toLowerCase() !== 'unknown')
            mfCounts[f] = (mfCounts[f] || 0) + 1;
    });
    const topMal = Object.entries(mfCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const mmax = topMal[0]?.[1] || 1;
    const malEl = document.getElementById('malFamilyList');
    if (malEl) {
        malEl.innerHTML = topMal.length
            ? topMal.map(([n, c]) => `
          <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #0f1a35">
            <span style="flex:1;font-size:11.5px;color:#cde0ff;font-weight:500">${n}</span>
            <div style="width:80px;height:4px;background:#0f1a35;border-radius:2px;overflow:hidden;flex-shrink:0">
              <div style="height:100%;width:${(c / mmax) * 100}%;background:#ff9800;border-radius:2px"></div>
            </div>
            <span style="font-size:12px;color:#ffffff;font-weight:800;min-width:35px;text-align:right">${c.toLocaleString()}</span>
          </div>`).join('')
            : '<div style="color:#3a5878;font-size:11px;padding:8px 0">No named families in current data.</div>';
    }
}

// ── IOC TYPE DISTRIBUTION ─────────────────────────────────────
function renderIocTypes(threats) {
    const typeCounts = {};
    threats.forEach(t => {
        const tp = t.type;
        if (tp && tp !== 'Unknown') typeCounts[tp] = (typeCounts[tp] || 0) + 1;
    });
    const el = document.getElementById('iocTypeChart');
    if (el && Object.keys(typeCounts).length) {
        mkChart('iocTypeChart', 'doughnut',
            Object.keys(typeCounts),
            [{
                data: Object.values(typeCounts),
                backgroundColor: ['#2979ff', '#ff3d5a', '#ff9800', '#00e5a0', '#9c6bff'],
                borderColor: '#060b18', borderWidth: 3
            }]
        );
    }
    const tbl = document.getElementById('iocTypeTable');
    const total = Object.values(typeCounts).reduce((a, b) => a + b, 0) || 1;
    if (tbl) {
        tbl.innerHTML = Object.entries(typeCounts)
            .sort((a, b) => b[1] - a[1])
            .map(([type, count]) => `
        <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #0f1a35">
          <span style="font-size:12px;color:#cde0ff;font-weight:600;min-width:55px">${type}</span>
          <div style="flex:1;height:4px;background:#0f1a35;border-radius:2px;overflow:hidden">
            <div style="height:100%;width:${(count / total) * 100}%;background:#2979ff;border-radius:2px"></div>
          </div>
          <span style="font-size:11px;color:#ffffff;font-weight:700;min-width:65px;text-align:right">
            ${count.toLocaleString()}
            <span style="color:#7a9cc8;font-size:10px;font-weight:400">(${Math.round((count / total) * 100)}%)</span>
          </span>
        </div>`).join('');
    }
}

// ── RISK & CVSS ───────────────────────────────────────────────
function renderRisk(threats) {
    const s = computeStats(threats);
    const avg = s.avg_cvss;
    const col = cvssColor(avg);
    const lbl = avg >= 9 ? 'Critical' : avg >= 7 ? 'High' : avg >= 4 ? 'Medium' : 'Low';

    const set = (id, v) => {
        const el = document.getElementById(id);
        if (el) el.textContent = typeof v === 'number' ? v.toLocaleString() : v;
    };

    set('avgCvss', avg.toFixed(1));
    const avgEl = document.getElementById('avgCvss');
    if (avgEl) avgEl.style.color = col;

    const ab = document.getElementById('avgCvssBar');
    if (ab) ab.style.cssText = `width:${(avg / 10) * 100}%;background:${col}`;
    set('avgCvssLbl', lbl + ' Risk Level');
    set('crit9Count', threats.filter(t => (t.cvss_score || 0) >= 9).length);
    set('critHighCount', s.critical + s.high);

    const top = [...threats].sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
    const maxSc = top[0]?.cvss_score || 0;
    set('maxCvss', maxSc.toFixed(1));
    const mb = document.getElementById('maxCvssBar');
    if (mb) mb.style.cssText = `width:${(maxSc / 10) * 100}%;background:#ff3d5a`;
    const maxEl = document.getElementById('maxCvssIoc');
    if (maxEl) {
        maxEl.textContent = (top[0]?.ioc || '—').substring(0, 30);
        maxEl.style.color = '#7a9cc8';
    }

    // Top 10 table — City replaces IOC (avoids redundancy with Threat Feed tab)
    const topBody = document.getElementById('topCvssBody');
    if (topBody) {
        topBody.innerHTML = top.slice(0, 10).map((t, i) => `
      <tr>
        <td style="color:#7a9cc8;font-weight:600">${i + 1}</td>
        <td><span style="font-family:monospace;font-size:13px;font-weight:800;color:${cvssColor(t.cvss_score || 0)}">${(t.cvss_score || 0).toFixed(1)}</span></td>
        <td>${sevBadge(t.severity)}</td>
        <td style="font-size:11px;color:#cde0ff;font-weight:500">${t.city || 'AU'}</td>
        <td style="font-size:11px;color:#cde0ff">${t.category || '—'}</td>
        <td><span class="badge badge-mitre" style="font-size:10px">${t.mitre_technique || '—'}</span></td>
        <td>${nistBadge(t.nist_function)}</td>
        <td><span class="badge badge-source" style="font-size:10px">${t.source || '—'}</span></td>
      </tr>`).join('');
    }

    // MITRE bars — weighted by cumulative CVSS score, not just count
    const mitreD = {};
    threats.forEach(t => {
        const tid = t.mitre_technique, nm = t.mitre_name;
        const score = t.cvss_score || 0;
        if (tid) {
            if (!mitreD[tid]) mitreD[tid] = { technique: tid, name: nm, count: 0, cvssTotal: 0 };
            mitreD[tid].count++;
            mitreD[tid].cvssTotal += score;
        }
    });
    // Sort by total CVSS weight — highest risk techniques surface first
    const mitreTop = Object.values(mitreD)
        .sort((a, b) => b.cvssTotal - a.cvssTotal)
        .slice(0, 8);
    const mmax2 = mitreTop[0]?.cvssTotal || 1;
    const mitreEl = document.getElementById('mitreList');
    if (mitreEl) {
        mitreEl.innerHTML = mitreTop.map(m => `
      <div style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid #0f1a35">
        <span style="font-family:monospace;font-size:11px;color:#ff7a90;font-weight:700;width:70px;flex-shrink:0">${m.technique}</span>
        <span style="font-size:11px;color:#cde0ff;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${m.name || 'Unknown'}</span>
        <span style="font-size:9.5px;color:#7a9cc8;min-width:28px;text-align:right" title="Occurrences">${m.count}</span>
        <div style="width:80px;height:4px;background:#0f1a35;border-radius:2px;flex-shrink:0;overflow:hidden">
          <div style="height:100%;width:${(m.cvssTotal / mmax2) * 100}%;background:#ff3d5a;border-radius:2px"></div>
        </div>
        <span style="font-size:12px;color:#ffffff;font-weight:800;min-width:52px;text-align:right" title="Total CVSS weight">${m.cvssTotal.toFixed(0)}</span>
      </div>`).join('');
    }

    // CVSS distribution chart
    const dist = s.cvss_dist;
    mkChart('cvssChart', 'bar',
        ['Critical\n9-10', 'High\n7-8.9', 'Medium\n4-6.9', 'Low\n0-3.9'],
        [{
            label: 'Threats',
            data: [dist.Critical || 0, dist.High || 0, dist.Medium || 0, dist.Low || 0],
            backgroundColor: ['#ff3d5a', '#ff9800', '#ffd740', '#00e5a0'],
            borderWidth: 0, borderRadius: 5
        }]
    );

    // Risk Matrix — draws after chart so canvas is sized
    setTimeout(() => drawRiskMatrix(threats), 80);

    // CVSS breakdown bars
    const dtotal = Math.max(Object.values(dist).reduce((a, b) => a + b, 0), 1);
    const cvssEl = document.getElementById('cvssDist');
    if (cvssEl) {
        cvssEl.innerHTML = [
            { l: 'Critical (9.0 - 10.0)', c: dist.Critical || 0, col: '#ff3d5a' },
            { l: 'High (7.0 - 8.9)', c: dist.High || 0, col: '#ff9800' },
            { l: 'Medium (4.0 - 6.9)', c: dist.Medium || 0, col: '#ffd740' },
            { l: 'Low (0.1 - 3.9)', c: dist.Low || 0, col: '#00e5a0' },
        ].map(i => `
      <div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;margin-bottom:4px">
          <span style="font-size:11.5px;color:${i.col};font-weight:600">${i.l}</span>
          <span style="font-size:12px;color:#ffffff;font-weight:800">${i.c.toLocaleString()} <span style="color:#7a9cc8;font-size:10px">(${Math.round((i.c / dtotal) * 100)}%)</span></span>
        </div>
        <div style="height:5px;background:#0f1a35;border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${(i.c / dtotal) * 100}%;background:${i.col};border-radius:3px"></div>
        </div>
      </div>`).join('');
    }
}

// ── ADDITIONAL CATEGORIES (overview tab) ─────────────────────
function renderAdditionalCats(s) {
    const el = document.getElementById('additionalCats');
    if (!el) return;
    const bonus = [
        { label: 'C2 Infrastructure', count: s.c2, col: '#a855f7' },
        { label: 'CVE References', count: s.category_counts['CVE'] || 0, col: '#0dd4f5' },
        { label: 'Web App Attacks', count: s.category_counts['Web App Attack'] || 0, col: '#f53d3d' },
        { label: 'DDoS Attacks', count: s.category_counts['DDoS Attack'] || 0, col: '#f5c842' },
        { label: 'Fraud Orders', count: s.category_counts['Fraud Orders'] || 0, col: '#f5820d' },
    ].filter(x => x.count > 0);

    el.innerHTML = bonus.map(b => `
    <div style="display:flex;align-items:center;justify-content:space-between;
      padding:6px 0;border-bottom:1px solid var(--bg3)">
      <span style="font-size:11.5px;color:var(--text2)">${b.label}</span>
      <span style="font-size:13px;font-weight:800;color:${b.col}">${b.count.toLocaleString()}</span>
    </div>`).join('') || '<div style="color:var(--text3);font-size:11px">No additional categories detected</div>';
}
// ── RISK MATRIX ───────────────────────────────────────────────
// ISO/IEC 27005:2022 — 5x5 Likelihood × Impact
// Called inside renderRisk() after existing content
function drawRiskMatrix(threats) {
    const canvas = document.getElementById('riskMatrix');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const wrap = canvas.parentElement;
    const W = (wrap ? wrap.offsetWidth : canvas.offsetWidth) || 560;
    const H = 250;
    canvas.width = W;
    canvas.height = H;

    const padL = 72, padB = 36, padT = 10, padR = 10;
    const cellW = (W - padL - padR) / 5;
    const cellH = (H - padT - padB) / 5;

    const likelihood = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost\nCertain'];
    const impact = ['Negligible', 'Minor', 'Moderate', 'Major', 'Catastrophic'];

    // Colour scale low→high risk
    const cellColor = (r, c) => {
        const score = (r + 1) * (c + 1); // 1–25
        if (score >= 20) return 'rgba(255,61,90,0.75)';
        if (score >= 12) return 'rgba(255,152,0,0.70)';
        if (score >= 6) return 'rgba(255,215,64,0.60)';
        return 'rgba(0,229,160,0.45)';
    };

    // Draw cells
    for (let r = 0; r < 5; r++) {
        for (let c = 0; c < 5; c++) {
            const x = padL + c * cellW;
            const y = padT + (4 - r) * cellH;
            ctx.fillStyle = cellColor(r, c);
            ctx.fillRect(x, y, cellW, cellH);
            ctx.strokeStyle = '#0a1628';
            ctx.lineWidth = 1;
            ctx.strokeRect(x, y, cellW, cellH);
        }
    }

    // X-axis labels (Likelihood)
    ctx.fillStyle = '#7a9cc8';
    ctx.font = '8.5px Inter, sans-serif';
    ctx.textAlign = 'center';
    likelihood.forEach((l, i) => {
        const x = padL + i * cellW + cellW / 2;
        const lines = l.split('\n');
        lines.forEach((line, li) => {
            ctx.fillText(line, x, H - padB + 12 + li * 10);
        });
    });

    // Y-axis labels (Impact)
    ctx.textAlign = 'right';
    impact.forEach((l, i) => {
        const y = padT + (4 - i) * cellH + cellH / 2 + 4;
        ctx.fillText(l, padL - 5, y);
    });

    // Axis titles
    ctx.fillStyle = '#00d68f';
    ctx.font = 'bold 9px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('LIKELIHOOD →', padL + (W - padL - padR) / 2, H - 2);

    ctx.save();
    ctx.translate(9, padT + (H - padT - padB) / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('IMPACT →', 0, 0);
    ctx.restore();

    // Risk positions — static expert assessment (ISO 27005)
    // Bubble SIZE = dynamic (live threat count) | COLOR = static (risk rating)
    const RISKS = [
        { label: 'Phishing', catKey: 'Phishing', l: 4, i: 3, col: '#ff9800' },
        { label: 'C2 Server', catKey: 'C2 Server', l: 3, i: 4, col: '#ff3d5a' },
        { label: 'Malware', catKey: 'Malware Distribution', l: 4, i: 2, col: '#ff9800' },
        { label: 'Brute Force', catKey: 'Brute Force', l: 3, i: 3, col: '#ffd740' },
        { label: 'Ransomware', catKey: 'Ransomware', l: 2, i: 4, col: '#ff3d5a' },
        { label: 'DDoS', catKey: 'DDoS Attack', l: 2, i: 3, col: '#ffd740' },
        { label: 'SQL Inject', catKey: 'SQL Injection', l: 2, i: 3, col: '#ffd740' },
        { label: 'Port Scan', catKey: 'Port Scan', l: 4, i: 1, col: '#00e5a0' },
    ];

    // Dynamic bubble size from live threat counts
    const catCounts = {};
    threats.forEach(t => { if (t.category) catCounts[t.category] = (catCounts[t.category] || 0) + 1; });
    const maxCount = Math.max(...Object.values(catCounts), 1);

    RISKS.forEach(risk => {
        const px = padL + risk.l * cellW - cellW / 2;
        const py = padT + (4 - risk.i) * cellH + cellH / 2;
        const count = catCounts[risk.catKey] || 0;
        // Min radius 6, max 16 — scaled by live data
        const radius = 6 + Math.round((count / maxCount) * 10);

        // Outer glow ring
        ctx.beginPath();
        ctx.arc(px, py, radius + 3, 0, Math.PI * 2);
        ctx.fillStyle = risk.col + '18';
        ctx.fill();

        // Main bubble
        ctx.beginPath();
        ctx.arc(px, py, radius, 0, Math.PI * 2);
        ctx.fillStyle = risk.col + '60';
        ctx.fill();
        ctx.strokeStyle = risk.col;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Count label inside bubble if big enough
        if (radius >= 10 && count > 0) {
            ctx.fillStyle = '#fff';
            ctx.font = `bold ${Math.min(radius - 2, 9)}px Inter, sans-serif`;
            ctx.textAlign = 'center';
            const label = count >= 1000 ? (count / 1000).toFixed(1) + 'k' : String(count);
            ctx.fillText(label, px, py + 3);
        }
    });

    // Legend
    const lel = document.getElementById('riskMatrixLbl');
    if (lel) lel.textContent = `${threats.length.toLocaleString()} threats plotted`;

    // Risk Register sidebar
    renderRiskRegister(threats);
}

function renderRiskRegister(threats) {
    const el = document.getElementById('riskRegister');
    if (!el) return;

    const REGISTER = [
        { id: 'R1', risk: 'Phishing', l: 5, i: 4, treatment: 'Restrict Office Macros · MFA', residual: 'Medium' },
        { id: 'R2', risk: 'C2 Server', l: 4, i: 5, treatment: 'Application Control', residual: 'Medium' },
        { id: 'R3', risk: 'Malware Distrib.', l: 5, i: 3, treatment: 'Patch Applications', residual: 'Medium' },
        { id: 'R4', risk: 'Brute Force', l: 4, i: 4, treatment: 'Multi-Factor Authentication', residual: 'Medium' },
        { id: 'R5', risk: 'Ransomware', l: 3, i: 5, treatment: 'Regular Backups · App Control', residual: 'Medium' },
        { id: 'R6', risk: 'SQL Injection', l: 3, i: 4, treatment: 'Patch Applications', residual: 'Medium' },
        { id: 'R7', risk: 'DDoS', l: 3, i: 4, treatment: 'Network / ISP Mitigation', residual: 'Medium' },
        { id: 'R8', risk: 'Port Scanning', l: 5, i: 2, treatment: 'Accept with Monitoring', residual: 'Medium' },
    ];

    const ratingColor = score =>
        score >= 20 ? '#ff3d5a' : score >= 12 ? '#ff9800' : score >= 6 ? '#ffd740' : '#00e5a0';
    const ratingLabel = score =>
        score >= 20 ? 'Critical' : score >= 12 ? 'High' : score >= 6 ? 'Medium' : 'Low';

    el.innerHTML = `
        <div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;
            font-weight:700;margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid var(--border)">
            Risk Register — ISO 27005
        </div>` +
        REGISTER.map(r => {
            const score = r.l * r.i;
            const col = ratingColor(score);
            const lbl = ratingLabel(score);
            return `
        <div style="display:flex;align-items:center;gap:7px;padding:5px 0;
            border-bottom:1px solid #0a1628;font-size:10.5px">
            <span style="color:var(--text3);min-width:22px;font-family:monospace;font-size:9.5px">${r.id}</span>
            <span style="flex:1;color:var(--text);font-weight:500">${r.risk}</span>
            <span style="font-family:monospace;font-weight:800;color:${col};min-width:18px;text-align:center">${score}</span>
            <span style="font-size:9px;font-weight:700;color:${col};min-width:44px;text-align:right">${lbl}</span>
        </div>`;
        }).join('') + `
        <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
            ${[['Critical', '#ff3d5a', '20-25'], ['High', '#ff9800', '12-19'], ['Medium', '#ffd740', '6-11'], ['Low', '#00e5a0', '1-5']]
            .map(([l, c, r]) => `<span style="font-size:9px;color:${c};font-weight:600">■ ${l} (${r})</span>`).join('')}
        </div>`;
}