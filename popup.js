const statusEl   = document.getElementById('status');
const predictBtn  = document.getElementById('predict');
const reportBtn   = document.getElementById('reportBtn');
const resultEl    = document.getElementById('result');
const resultIcon  = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultDetail= document.getElementById('resultDetail');
const scanBar     = document.getElementById('scanBar');
const statusDot   = document.getElementById('statusDot');

// ── Helpers ──────────────────────────────────────────────
function setStatus(text, mode = '') {
  statusEl.textContent = text;
  statusEl.className = mode; // 'danger' | 'safe' | 'scan' | ''
}

function setScanning(active) {
  document.body.classList.toggle('scanning', active);
  scanBar.classList.toggle('active', active);
  predictBtn.disabled = active;
  predictBtn.textContent = active ? '◈ Scanning...' : '⬡ Scan Site';
}

function showResult(prediction, source, probability) {
  resultEl.style.display = 'block';
  resultEl.className = ''; // reset classes

  const prob = probability != null ? `${(probability * 100).toFixed(1)}%` : null;
  const src  = source ? `SOURCE · ${source.toUpperCase()}` : '';

  if (prediction === 'phishing') {
    resultEl.classList.add('phishing');
    resultIcon.textContent  = '☠';
    resultTitle.textContent = 'THREAT DETECTED';
    resultDetail.textContent = `${prob ? 'Confidence · ' + prob + '   ' : ''}${src}`;
    setStatus('⚠ Phishing site identified — do not proceed', 'danger');
  } else if (prediction === 'suspicious') {
    resultEl.classList.add('suspicious');
    resultIcon.textContent  = '⚡';
    resultTitle.textContent = 'ANOMALY DETECTED';
    resultDetail.textContent = `${prob ? 'Risk · ' + prob + '   ' : ''}${src}`;
    setStatus('Suspicious signals detected — proceed with caution', 'scan');
  } else {
    resultEl.classList.add('safe');
    resultIcon.textContent  = '✔';
    resultTitle.textContent = 'SITE SECURE';
    resultDetail.textContent = `${prob ? 'Risk · ' + prob + '   ' : ''}${src}`;
    setStatus('No threats detected — connection secure', 'safe');
  }
}

function hideResult() {
  resultEl.style.display = 'none';
  resultEl.className = '';
}

// ── Get current tab URL ───────────────────────────────────
async function getActiveTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url ?? null;
  } catch (e) {
    console.error('tabs.query failed', e);
    return null;
  }
}

// ── Main scan ─────────────────────────────────────────────
async function predictSite() {
  hideResult();
  reportBtn.style.display = 'none';
  setScanning(true);

  const url = await getActiveTabUrl();

  if (!url) {
    setStatus('ERROR · No active tab URL found', 'danger');
    setScanning(false);
    return;
  }

  // Animated status cycle while fetching
  const dots = ['Initializing scan', 'Running ML analysis', 'Cross-referencing database', 'Computing threat score'];
  let di = 0;
  setStatus(dots[di], 'scan');
  const ticker = setInterval(() => {
    di = (di + 1) % dots.length;
    setStatus(dots[di] + '...', 'scan');
  }, 700);

  try {
    const resp = await fetch('https://phishguard-production-c380.up.railway.app/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    clearInterval(ticker);

    if (!resp.ok) {
      setStatus(`SERVER ERROR · ${resp.status}`, 'danger');
      return;
    }

    const data = await resp.json();
    const { prediction, source, probability } = data;

    showResult(prediction, source, probability);

    if (prediction === 'phishing' || prediction === 'suspicious') {
      reportBtn.style.display = 'block';
      reportBtn.onclick = () => reportPhishing(url);
    }

  } catch (err) {
    clearInterval(ticker);
    console.error(err);
    setStatus('CONNECTION FAILED · Backend unreachable', 'danger');
    hideResult();
  } finally {
    setScanning(false);
  }
}

// ── Report phishing ───────────────────────────────────────
async function reportPhishing(url) {
  try {
    const isFalsePositive = confirm(
      'Is this a FALSE POSITIVE?\n\nOK = False Positive (site is safe)\nCancel = Confirm as phishing'
    );
    const action = isFalsePositive ? 'false_positive' : 'new';

    const resp = await fetch('https://phishguard-production-c380.up.railway.app/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url,
        confidence: isFalsePositive ? '0.0' : 'manual-report',
        model:      isFalsePositive ? 'manual_false_positive' : 'manual_report',
        action
      })
    });

    const data = await resp.json();
    alert(data.message || 'Report submitted successfully.');
    reportBtn.style.display = 'none';
  } catch (err) {
    console.error(err);
    alert('Failed to submit report — check backend connection.');
  }
}

// ── Init ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  predictBtn.addEventListener('click', predictSite);
  setStatus('Awaiting scan command...');
});
