/* ============================================================
   table.js — Threat Feed DataTable
   High contrast text, clean columns, working filters
   ============================================================ */

function renderTable(threats) {
    const tbody = document.getElementById('iocBody');
    if (!tbody) return;

    // Destroy any existing DataTable instance first, before touching
    // innerHTML. NOTE: do NOT use { remove: true } here — that option
    // deletes the <table> element itself from the DOM, which breaks
    // every subsequent call to renderTable() since #iocBody no longer
    // exists to write rows into (table appears empty after 1st filter).
    // Default destroy() keeps the table/rows in the DOM and only tears
    // down DataTables' own wrapper chrome (search box, paging controls,
    // scrollX clones) — which is what we actually want before reinit.
    if (window.DT) { window.DT.destroy(); window.DT = null; }

    // Render top 500 for performance
    const display = threats.slice(0, 500);

    // Severity sort rank — used for default ordering
    const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };

    tbody.innerHTML = display.map(t => {
        // Sortable ISO timestamp hidden in a data attribute —
        // DataTables sorts strings alphabetically, so "22/04/2026" (DD/MM/YYYY)
        // sorts wrong unless we give it a real sortable value.
        const sortableTs = t.timestamp_utc || '';
        const sevRank = SEV_RANK[t.severity] ?? 4;

        return `
    <tr data-sev-rank="${sevRank}" data-ts="${sortableTs}">
      <td>${sevBadge(t.severity)}</td>
      <td>
        <span style="font-family:monospace;font-size:13px;font-weight:800;
          color:${cvssColor(t.cvss_score || 0)}">${(t.cvss_score || 0).toFixed(1)}</span>
      </td>
      <td>
        <span style="font-size:11px;color:#00d4ff;font-weight:700;
          background:rgba(0,212,255,.08);padding:2px 7px;border-radius:4px;
          border:1px solid rgba(0,212,255,.2)">${t.type || '—'}</span>
      </td>
      <td>
        <span style="font-family:monospace;font-size:11px;color:#00d4ff;
          display:block;max-width:200px;overflow:hidden;
          text-overflow:ellipsis;white-space:nowrap"
          title="${t.ioc || ''}">${(t.ioc || '').substring(0, 38)}</span>
      </td>
      <td style="font-size:11.5px;color:#cde0ff;font-weight:500">${t.category || '—'}</td>
      <td>${mitreBadge(t.mitre_technique)}</td>
      <td>${nistBadge(t.nist_function)}</td>
      <td style="font-size:10.5px;color:#cde0ff">${t.asd_e8 || '—'}</td>
      <td style="font-size:11px;color:#7a9cc8">${t.industry || 'Other'}</td>
      <td><span class="badge badge-source">${t.source || '—'}</span></td>
      <td style="font-size:11px;color:#cde0ff;font-weight:500">${t.city || 'AU'}</td>
      <td data-order="${sortableTs}" style="font-size:10px;color:#7a9cc8;white-space:nowrap">${t.timestamp_au || t.timestamp_utc || '—'}</td>
    </tr>`;
    }).join('');

    // Update export button with count
    const expBtn = document.getElementById('exportBtn');
    if (expBtn) expBtn.textContent = `⬇ Export ${display.length.toLocaleString()} CSV`;

    // We already destroyed any previous DataTable instance above,
    // before the rows were rebuilt, so this init binds cleanly to
    // the current #iocTable / #iocBody markup with no stale state.
    window.DT = new DataTable('#iocTable', {
        pageLength: 15,
        // Default: Severity ascending (Critical→Low) using row data-sev-rank,
        // tie-broken by Timestamp descending (newest first) on column 11.
        // Column 0 is the visible severity badge — we use a custom sort
        // via the hidden data-sev-rank attribute for correct triage order.
        order: [[11, 'desc']],
        // Actual page-length choices — without this array, the
        // "Show _MENU_" language template has nothing to render,
        // leaving an empty dropdown.
        lengthMenu: [[10, 15, 25, 50, 100, -1], [10, 15, 25, 50, 100, 'All']],
        columnDefs: [
            { targets: '_all', defaultContent: '—' },
            {
                targets: 0,
                orderDataType: 'dom-data-sev-rank',
            },
        ],
        scrollX: true,
        deferRender: true,
        language: {
            search: 'Search:',
            lengthMenu: 'Show _MENU_ rows',
            info: 'Showing _START_ to _END_ of _TOTAL_ threats',
        },
    });

    // Re-apply correct default order: severity rank asc, then timestamp desc
    window.DT.order([[0, 'asc'], [11, 'desc']]).draw();

    const el = document.getElementById('filterCount');
    if (el) el.textContent = `Showing ${threats.length.toLocaleString()} of ${window.ALL.length.toLocaleString()} threats`;
}

// Custom DataTables sort type reading the row's data-sev-rank attribute
// so Critical (0) sorts before High (1) before Medium (2) before Low (3)
$.fn.dataTable.ext.order['dom-data-sev-rank'] = function (settings, col) {
    return this.api().column(col, { order: 'index' }).nodes().map(td => {
        const row = td.closest('tr');
        return parseInt(row?.dataset.sevRank ?? 4, 10);
    });
};

window.exportCSV = () => {
    const threats = window.FILTERED || window.ALL;
    const headers = ['severity', 'cvss_score', 'type', 'ioc', 'category',
        'mitre_technique', 'nist_function', 'asd_e8',
        'industry', 'source', 'city', 'timestamp_au'];
    const rows = threats.map(t =>
        headers.map(h => `"${(t[h] || '').toString().replace(/"/g, '""')}"`).join(',')
    );
    const csv = [headers.join(','), ...rows].join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `au-cti-group14-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
};