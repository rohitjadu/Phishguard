// ── PhishGuard Dashboard Live Updater ──────────────────────────────────────

async function fetchDashboardData() {
    try {
        const params = new URLSearchParams(window.location.search);
        const res = await fetch('/reports.json?' + params.toString());
        if (!res.ok) { console.warn('reports.json returned', res.status); return; }
        const data = await res.json();
        if (data.error) { console.warn('reports.json error:', data.error); return; }

        // ── Total count ──────────────────────────────────
        const totalBadge = document.getElementById('total-badge');
        if (totalBadge) totalBadge.textContent = data.total ?? 0;

        // ── Row count badge ──────────────────────────────
        const rowCount = document.getElementById('row-count');
        if (rowCount && data.rows) rowCount.textContent = data.rows.length + ' records';

        // ── Download link with filters ───────────────────
        const downloadLink = document.getElementById('download-link');
        if (downloadLink) downloadLink.href = '/download-csv?' + params.toString();

        // ── Source distribution bars ─────────────────────
        const ss = document.getElementById('source-stats');
        if (ss && data.source_percentages && Object.keys(data.source_percentages).length > 0) {
            ss.innerHTML = Object.entries(data.source_percentages).map(([s, pct]) => {
                const count = (data.source_stats && data.source_stats[s]) ? data.source_stats[s] : 0;
                const pctNum = Number(pct) || 0;
                return `
                    <div class="source-bar-row">
                        <span class="source-name">${s}</span>
                        <div class="source-bar-track">
                            <div class="source-bar-fill" style="width:${pctNum}%"></div>
                        </div>
                        <span class="source-pct">${pctNum.toFixed(1)}%</span>
                        <span class="source-count">${count}</span>
                    </div>`;
            }).join('');
        }

        // ── Threat log table ─────────────────────────────
        const tbody = document.getElementById('reports-tbody');
        if (tbody && Array.isArray(data.rows)) {
            if (data.rows.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="td-empty">— No threat records match current filters —</td></tr>';
                return;
            }
            tbody.innerHTML = data.rows.map(r => {
                const conf = parseFloat(r.confidence);
                const confClass = isNaN(conf) ? 'low' : conf >= 0.8 ? 'high' : conf >= 0.5 ? 'mid' : 'low';
                const confText = (v => (isNaN(v) || v == null) ? (r.confidence ?? '—') : v.toFixed(2))(conf);
                
                // Handle NaT (Not a Time) from pandas
                let ts = String(r.timestamp || '—');
                if (ts === 'NaT' || ts === 'nan' || ts === 'None') ts = '—';
                
                const url = escapeHtml(r.url || '—');
                const model = escapeHtml(r.model || '—');
                const source = escapeHtml(r.source || '—');
                
                return `
                    <tr>
                        <td class="td-time">${escapeHtml(ts)}</td>
                        <td class="td-url"><a href="${url === '—' ? '#' : url}" target="_blank" rel="noopener">${url}</a></td>
                        <td><span class="conf-badge ${confClass}">${escapeHtml(String(confText))}</span></td>
                        <td><span class="tag model-tag">${model}</span></td>
                        <td><span class="tag source-tag">${source}</span></td>
                    </tr>`;
            }).join('');
        }

    } catch (e) {
        console.error('Dashboard update error:', e);
    }
}

// Safely escape HTML to prevent XSS in URL links
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ── Run immediately + poll every 10s ───────────────────────────────────────
fetchDashboardData();
setInterval(fetchDashboardData, 10000);