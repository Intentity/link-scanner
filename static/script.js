const form = document.getElementById('scan-form');
const input = document.getElementById('url-input');
const runBtn = document.getElementById('run-btn');
const errorMsg = document.getElementById('error-msg');
const results = document.getElementById('results');

const gaugeFill = document.getElementById('gauge-fill');
const gaugeScore = document.getElementById('gauge-score');
const verdictLevel = document.getElementById('verdict-level');
const verdictHost = document.getElementById('verdict-host');
const categoryTags = document.getElementById('category-tags');
const logBody = document.getElementById('log-body');
const logCount = document.getElementById('log-count');

const GAUGE_CIRCUMFERENCE = 440;

const LEVEL_COLOR = {
  low: 'var(--low)',
  medium: 'var(--medium)',
  high: 'var(--high)',
  critical: 'var(--critical)',
};

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  errorMsg.hidden = true;

  if (!url) {
    errorMsg.textContent = 'Enter a URL to scan.';
    errorMsg.hidden = false;
    return;
  }

  runBtn.disabled = true;
  runBtn.textContent = 'SCANNING…';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    if (!res.ok) {
      errorMsg.textContent = data.error || 'Something went wrong.';
      errorMsg.hidden = false;
      results.hidden = true;
      return;
    }

    renderResult(data);
  } catch (err) {
    errorMsg.textContent = 'Could not reach the scanner. Is the server running?';
    errorMsg.hidden = false;
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = 'RUN';
  }
});

function renderResult(data) {
  results.hidden = false;

  // Gauge
  const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * data.score) / 100;
  gaugeFill.style.stroke = LEVEL_COLOR[data.risk_level] || 'var(--ok)';
  // force reflow so the transition animates from previous value
  gaugeFill.style.transition = 'none';
  gaugeFill.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  void gaugeFill.offsetHeight;
  gaugeFill.style.transition = '';
  gaugeFill.style.strokeDashoffset = offset;

  gaugeScore.textContent = data.score;

  verdictLevel.textContent = `${data.risk_level} risk`;
  verdictLevel.style.color = LEVEL_COLOR[data.risk_level] || 'var(--ok)';
  verdictHost.textContent = data.host || data.normalized_url;

  categoryTags.innerHTML = '';
  if (data.likely_categories.length === 0) {
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.textContent = 'No specific threat pattern matched';
    categoryTags.appendChild(tag);
  } else {
    data.likely_categories.forEach((cat) => {
      const tag = document.createElement('span');
      tag.className = 'tag';
      tag.textContent = cat;
      categoryTags.appendChild(tag);
    });
  }

  // Log
  logBody.innerHTML = '';
  const triggeredCount = data.findings.filter((f) => f.triggered).length;
  logCount.textContent = `${triggeredCount} flagged / ${data.findings.length} checks`;

  data.findings.forEach((f) => {
    const line = document.createElement('div');
    line.className = 'log-line';

    const status = document.createElement('div');
    status.className = `log-status ${f.triggered ? f.severity : 'ok'}`;
    status.textContent = f.triggered ? `[FLAG:${f.severity.toUpperCase()}]` : '[OK]';

    const textWrap = document.createElement('div');
    textWrap.className = 'log-text';

    const title = document.createElement('div');
    title.className = 'log-title';
    title.textContent = f.label;
    textWrap.appendChild(title);

    if (f.triggered && f.detail) {
      const detail = document.createElement('div');
      detail.className = 'log-detail';
      detail.textContent = f.detail;
      textWrap.appendChild(detail);
    }

    if (f.triggered && f.category) {
      const cat = document.createElement('div');
      cat.className = 'log-category';
      cat.textContent = `→ ${f.category}`;
      textWrap.appendChild(cat);
    }

    line.appendChild(status);
    line.appendChild(textWrap);
    logBody.appendChild(line);
  });
}
