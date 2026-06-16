/* ============================================================
   table.js — Threat Feed DataTable
   High contrast text, clean columns, working filters
   ============================================================ */

function renderTable(threats) {
    const tbody = document.getElementById('iocBody');
    if (!tbody) return;

    // Render top 500 for performance
    const display = threats.slice(0, 500);

    tbody.innerHTML = display.map(t => `
    <tr>
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
      <td style="font-size:10px;color:#7a9cc8;white-space:nowrap">${t.timestamp_au || t.timestamp_utc || '—'}</td>
    </tr>`).join('');

    if (window.DT) { window.DT.destroy(); window.DT = null; }
    window.DT = new DataTable('#iocTable', {
        pageLength: 15,
        order: [[1, 'desc']],
        scrollX: true,
        deferRender: true,
        language: {
            search: 'Search:',
            lengthMenu: 'Show _MENU_',
            info: 'Showing _START_ to _END_ of _TOTAL_ threats',
        },
        columnDefs: [{ targets: '_all', defaultContent: '—' }],
    });

    const el = document.getElementById('filterCount');
    if (el) el.textContent = `Showing ${threats.length.toLocaleString()} of ${window.ALL.length.toLocaleString()} threats`;
}

window.exportCSV = () => {
    const threats = window.FILTERED.length ? window.FILTERED : window.ALL;
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