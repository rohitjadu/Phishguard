const statusEl = document.getElementById('status');
const predictBtn = document.getElementById('predict');
const reportBtn = document.getElementById('reportBtn');
const resultEl = document.getElementById('result');

function setStatus(text, color = '#333') {
  statusEl.textContent = text;
  statusEl.style.color = color;
}

function showResult(message, type) {
  resultEl.textContent = message;
  resultEl.className = ''; // reset
  resultEl.style.display = 'block';
  if (type === 'phishing') {
    resultEl.classList.add('phishing');
  } else if (type === 'safe') {
    resultEl.classList.add('safe');
  }
}

function setButtonLoading(loading) {
  predictBtn.disabled = loading;
  predictBtn.textContent = loading ? 'Checking...' : '🔍 Check Site';
}

// Get current tab URL
async function getActiveTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url ?? null;
  } catch (e) {
    console.error('tabs.query failed', e);
    return null;
  }
}

// Predict phishing or safe
async function predictSite() {
  resultEl.style.display = 'none';
  reportBtn.style.display = 'none';
  setButtonLoading(true);
  const url = await getActiveTabUrl();

  if (!url) {
    setStatus('No active tab URL found', 'red');
    setButtonLoading(false);
    return;
  }

  setStatus(`Analyzing: ${url}`, '#555');

  try {
  const resp = await fetch('http://127.0.0.1:8001/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!resp.ok) {
      showResult(`Server error: ${resp.status}`, 'error');
      setStatus('Server error occurred', 'red');
      return;
    }

    const data = await resp.json();
    const { prediction, source } = data;
    const color = prediction === 'phishing' ? 'red' : 'green';

    setStatus(
      `Result: ${prediction.toUpperCase()} (source: ${source})`,
      color
    );
    showResult(`Prediction: ${prediction}`, prediction);

    // Show report button only if phishing
    if (prediction === 'phishing') {
      reportBtn.style.display = 'block';
      reportBtn.onclick = () => reportPhishing(url);
    }
  } catch (err) {
    console.error(err);
    showResult('Failed to contact server — is FastAPI running?', 'error');
    setStatus('Backend not reachable', 'red');
  } finally {
    setButtonLoading(false);
  }
}

// Report phishing manually
async function reportPhishing(url) {
  try {
    // Ask user if this is a false positive. OK = false positive, Cancel = new/other
    const isFalsePositive = confirm('Is this a FALSE POSITIVE? Click OK for False Positive, Cancel to report as a new/manual report.');
    const action = isFalsePositive ? 'false_positive' : 'new';

    const resp = await fetch('http://127.0.0.1:8001/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url,
        confidence: isFalsePositive ? '0.0' : 'manual-report',
        model: isFalsePositive ? 'manual_false_positive' : 'manual_report',
        action: action
      })
    });
    const data = await resp.json();
    alert(data.message || 'Phishing URL reported successfully!');
    reportBtn.style.display = 'none';
  } catch (err) {
    console.error(err);
    alert('Failed to report phishing URL — check backend connection.');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  predictBtn.addEventListener('click', predictSite);
  setStatus('Ready — click "Check Site" to analyze.');
});
