/* ============================================================
   ir.js — IR & Mitigation Tab v5
   Inline accordion — compact, no separate panel
   ============================================================ */

let IR_DATA = {};
let expandedRow = null;

function irSevColor(s) {
  return { Critical: 'var(--red)', High: 'var(--orange)', Medium: 'var(--yellow)', Low: 'var(--green)' }[s] || 'var(--text2)';
}
function nistColor(fn) {
  return { Identify: 'var(--green)', Protect: '#6ba3ff', Detect: 'var(--orange)', Respond: 'var(--red)', Recover: 'var(--purple)' }[fn] || 'var(--text2)';
}

// ── SUMMARY TABLE ─────────────────────────────────────────────
function renderIRSummary() {
  const summary = IR_DATA.summary || [];
  const tbody = document.getElementById('irSummaryBody');
  if (!tbody || !summary.length) return;

  tbody.innerHTML = summary.map((r, idx) => `
        <tr class="ir-main-row" data-idx="${idx}" onclick="togglePlaybook(${idx}, '${r.category}')">
            <td>
                <button class="ir-toggle-btn" id="ir-toggle-${idx}">›</button>
            </td>
            <td><b style="color:var(--text)">${r.category}</b></td>
            <td><span style="font-size:11px;font-weight:600;color:${irSevColor(r.severity)}">${r.severity}</span></td>
            <td><span class="badge badge-mitre">${r.mitre.split('—')[0].trim()}</span></td>
            <td><span style="font-size:11px;color:${nistColor(r.nist)}">${r.nist}</span></td>
            <td style="font-size:11px;color:var(--text2)">${r.asd_e8}</td>
            <td><span style="font-size:11px;font-weight:600;color:${r.severity === 'Critical' ? 'var(--red)' : 'var(--orange)'}">${r.response_time}</span></td>
        </tr>
        <tr class="ir-expand-row" id="ir-detail-${idx}" style="display:none">
            <td colspan="7"></td>
        </tr>`).join('');
}

// ── INLINE ACCORDION ──────────────────────────────────────────
function togglePlaybook(idx, category) {
  const detailRow = document.getElementById(`ir-detail-${idx}`);
  const toggleBtn = document.getElementById(`ir-toggle-${idx}`);
  if (!detailRow) return;

  const isOpen = detailRow.style.display !== 'none';

  // Close previously open row
  if (expandedRow !== null && expandedRow !== idx) {
    const prev = document.getElementById(`ir-detail-${expandedRow}`);
    const prevBtn = document.getElementById(`ir-toggle-${expandedRow}`);
    if (prev) prev.style.display = 'none';
    if (prevBtn) prevBtn.classList.remove('open');
  }

  if (isOpen) {
    detailRow.style.display = 'none';
    toggleBtn?.classList.remove('open');
    expandedRow = null;
  } else {
    populateDetail(idx, category, detailRow);
    detailRow.style.display = 'table-row';
    toggleBtn?.classList.add('open');
    expandedRow = idx;
  }
}

// ── POPULATE INLINE DETAIL ────────────────────────────────────
function populateDetail(idx, category, detailRow) {
  const playbooks = IR_DATA.playbooks || {};
  const p = playbooks[category];
  if (!p) { detailRow.cells[0].innerHTML = '<div style="padding:12px;color:var(--text3)">No detail available.</div>'; return; }

  const mit = p.mitigation || {};
  const phases = Object.entries(p.phases || {});

  const shortItems = (mit.short_term || []).slice(0, 4).map(i =>
    `<div class="ir-detail-item">${i}</div>`).join('');
  const longItems = (mit.long_term || []).slice(0, 4).map(i =>
    `<div class="ir-detail-item">${i}</div>`).join('');
  const fixItems = (p.vulnerability_fixes || []).slice(0, 4).map(i =>
    `<div class="ir-detail-item">${i}</div>`).join('');
  const contacts = (p.au_contacts || []).slice(0, 4).map(c =>
    `<div style="font-size:10.5px;color:var(--cyan);padding:3px 0;border-bottom:1px solid var(--bg2)">${c}</div>`).join('');

  const phasesHtml = phases.map(([phase, actions], i) => `
        <div class="ir-phase-mini">
            <div class="ir-phase-mini-title">${i + 1}. ${phase}</div>
            <ul style="padding:0;margin:0">
                ${(actions || []).slice(0, 3).map(a => `<li>${a}</li>`).join('')}
            </ul>
        </div>`).join('');

  detailRow.cells[0].innerHTML = `
        <div class="ir-detail-panel">
            <div class="ir-detail-col">
                <div class="ir-detail-col-title">Short-Term Actions</div>
                ${shortItems || '<div class="ir-detail-item" style="color:var(--text3)">—</div>'}
            </div>
            <div class="ir-detail-col">
                <div class="ir-detail-col-title">Long-Term Actions</div>
                ${longItems || '<div class="ir-detail-item" style="color:var(--text3)">—</div>'}
            </div>
            <div class="ir-detail-col">
                <div class="ir-detail-col-title">Vulnerability Fixes</div>
                ${fixItems || '<div class="ir-detail-item" style="color:var(--text3)">—</div>'}
            </div>
            <div class="ir-detail-col">
                <div class="ir-detail-col-title" style="color:var(--red)">AU Reporting Contacts</div>
                ${contacts || '<div style="font-size:10.5px;color:var(--text3)">—</div>'}
                <div style="margin-top:8px;padding:7px 9px;background:rgba(255,69,69,.06);
                    border:1px solid rgba(255,69,69,.2);border-radius:5px;font-size:9.5px;color:var(--text2)">
                    <div style="color:var(--red);font-weight:700;margin-bottom:3px">Mandatory Obligations</div>
                    <div>· Privacy Act 1988 — OAIC within 30 days</div>
                    <div>· SOCI Act 2018 — ASD within 12 hours</div>
                    <div>· Ransomware — ACSC 1300 CYBER1</div>
                </div>
            </div>
            <div class="ir-phases-mini">
                ${phasesHtml}
            </div>
        </div>`;
}

// ── INIT ──────────────────────────────────────────────────────
function initIR(irData) {
  IR_DATA = irData || {};
  renderIRSummary();
}