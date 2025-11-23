// Poll /reports.json every 5 seconds and update the table and stats
async function fetchDashboardData() {
    try {
        const params = new URLSearchParams(window.location.search);
        const res = await fetch('/reports.json?' + params.toString());
        if (!res.ok) return;
        const data = await res.json();
        if (data.error) return;

        // Update total
        const totalBadge = document.getElementById('total-badge');
        if (totalBadge) totalBadge.textContent = data.total;

        // Update download link to include current filters
        const downloadLink = document.getElementById('download-link');
        if (downloadLink) downloadLink.href = '/download-csv?' + params.toString();

        // Update source stats
        const ss = document.getElementById('source-stats');
        if (ss && data.source_percentages) {
            ss.innerHTML = Object.keys(data.source_percentages).map(s => {
                const pct = data.source_percentages[s] || 0;
                const count = data.source_stats && data.source_stats[s] ? data.source_stats[s] : 0;
                return `
                    <div class="source-stat-item mb-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <span class="badge bg-info">${s}</span>
                            <span class="badge bg-secondary">${count} (${pct}%)</span>
                        </div>
                        <div class="progress mt-1" style="height: 4px;">
                            <div class="progress-bar" role="progressbar" style="width: ${pct}%"></div>
                        </div>
                    </div>`;
            }).join('');
        }

        // Update table rows
        const tbody = document.getElementById('reports-tbody');
        if (tbody && Array.isArray(data.rows)) {
            tbody.innerHTML = data.rows.map(r => `
                <tr>
                    <td>${r.timestamp}</td>
                    <td><a href='${r.url}' target='_blank' class="text-break">${r.url}</a></td>
                    <td><span class="${getConfidenceClass(r.confidence)}">${formatConfidence(r.confidence)}</span></td>
                    <td><span class="badge bg-secondary">${r.model || ''}</span></td>
                    <td><span class="badge bg-info">${r.source || ''}</span></td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error('Dashboard update error:', e);
    }
}

function getConfidenceClass(confidence) {
    if (confidence === undefined || confidence === null) return 'text-muted';
    const conf = parseFloat(confidence);
    if (isNaN(conf)) return 'text-muted';
    return conf >= 0.8 ? 'text-success' : conf >= 0.5 ? 'text-warning' : 'text-danger';
}

function formatConfidence(confidence) {
    if (confidence === undefined || confidence === null) return '';
    const conf = parseFloat(confidence);
    return isNaN(conf) ? '' : conf.toFixed(2);
}

// Start polling
fetchDashboardData();
setInterval(fetchDashboardData, 5000);