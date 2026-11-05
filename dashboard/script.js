const API = 'http://localhost:8001';
let rawLogs = [], normalizedLogs = [], alerts = [];
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const time = value => {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? esc(value) : d.toLocaleString();
};
const sev = value => {
  const s = String(value || 'info').toLowerCase();
  return ['critical','high','medium','low','info','informational'].includes(s) ? s : 'info';
};
const message = item => item.message || item.Message || item.raw?.message || item.description || '—';

async function get(path) {
  const response = await fetch(API + path);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function refreshData() {
  try {
    const [stats, raw, normalized, alertData] = await Promise.all([
      get('/api/stats'), get('/api/raw-logs?limit=300'),
      get('/api/normalized-logs?limit=300'), get('/api/alerts?limit=300')
    ]);
    rawLogs = raw; normalizedLogs = normalized; alerts = alertData;
    $('raw-count').textContent = stats.raw_events ?? raw.length;
    $('normalized-count').textContent = stats.normalized_events ?? normalized.length;
    $('alert-count').textContent = stats.alerts ?? alertData.length;
    $('critical-count').textContent = stats.critical_alerts ?? alertData.filter(a=>sev(a.severity)==='critical').length;
    $('alert-total-tag').textContent = `${alertData.length} ALERTS`;
    renderAlerts(); renderRaw(); renderNormalized(); renderOverview();
    $('last-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (error) {
    $('last-updated').textContent = 'API CONNECTION ERROR';
    toast('Backend unavailable: ' + error.message);
  }
}


function alertForRaw(raw) {
  const rawMessage = message(raw).trim().toLowerCase();
  const rawHost = String(
    typeof raw.host === 'object' ? raw.host?.name || '' : raw.host || ''
  ).toLowerCase();

  const rawTime = new Date(raw['@timestamp'] || raw.timestamp).getTime();

  return alerts.find(a => {
    const event = a.event || {};
    const mapped = a.mapped_event || {};

    const alertHost = String(
      a.host || event.host?.name || event.host || mapped.Computer || ''
    ).toLowerCase();

    if (rawHost && alertHost && rawHost !== alertHost) return false;

    const messages = [
      event.message,
      event.raw?.message,
      mapped.message,
      mapped.CommandLine,
      mapped.command_line,
      a.message
    ].filter(Boolean).map(x => String(x).trim().toLowerCase());

    if (rawMessage && messages.includes(rawMessage)) return true;

    const alertTime = new Date(
      a.timestamp || event.timestamp || event['@timestamp']
    ).getTime();

    return Number.isFinite(rawTime) &&
      Number.isFinite(alertTime) &&
      Math.abs(rawTime - alertTime) <= 2000 &&
      (!rawHost || !alertHost || rawHost === alertHost);
  });
}


function jsonDetails(event, label) {
  return `<details class="event-details">
    <summary>${label}</summary>
    <pre>${esc(JSON.stringify(event, null, 2))}</pre>
  </details>`;
}

function renderRaw() {
  const q = ($('raw-search').value || '').toLowerCase();
  const rows = rawLogs.map((event, index) => ({event, index}))
    .filter(x => JSON.stringify(x.event).toLowerCase().includes(q));

  $('raw-table').innerHTML = rows.length ? rows.map(({event:x, index}) => {
    const matched = alertForRaw(x);
    const severity = matched ? sev(matched.severity) : '';

    return `<tr>
      <td class="mono">${esc(time(x['@timestamp'] || x.timestamp))}</td>
      <td>${esc(x.host?.name || x.host || x.hostname)}</td>
      <td>${esc(x.log_source || x.source || x.event?.dataset || '—')}</td>
      <td>${esc(message(x))}</td>
      <td>${matched
        ? `<span class="severity ${severity}">${esc(matched.severity || 'ALERT')}</span>
           <button class="text-btn" data-goto="alerts">View alerts</button>`
        : '<span class="tag">NO ALERT</span>'}</td>
      <td>${jsonDetails(x, 'View complete raw event')}</td>
      <td><button class="analyze" data-log-type="raw" data-log-index="${index}">✦ Analyze</button></td>
    </tr>`;
  }).join('') : '<tr><td colspan="7" class="empty">No raw events found</td></tr>';
}

function renderNormalized() {
  const q = ($('normalized-search').value || '').toLowerCase();
  const rows = normalizedLogs.map((event, index) => ({event, index}))
    .filter(x => JSON.stringify(x.event).toLowerCase().includes(q));

  $('normalized-table').innerHTML = rows.length ? rows.map(({event:x, index}) => `<tr>
    <td class="mono">${esc(time(x.timestamp))}</td>
    <td>${esc(x.host || x.Computer)}</td>
    <td>${esc(x.source || x.category || '—')}</td>
    <td>${esc(x.username || x.User || '—')}</td>
    <td>${esc(message(x))}</td>
    <td>${jsonDetails(x, 'View all normalized fields')}</td>
    <td><button class="analyze" data-log-type="normalized" data-log-index="${index}">✦ Analyze</button></td>
  </tr>`).join('') : '<tr><td colspan="7" class="empty">No normalized events found</td></tr>';
}
function renderAlerts() {
  const q = ($('alert-search').value || '').toLowerCase();
  const rows = alerts.filter(a => JSON.stringify(a).toLowerCase().includes(q));
  $('alerts-table').innerHTML = rows.length ? rows.map(a => {
    const title = a.rule?.title || a.title || 'Security alert';
    return `<tr>
      <td><span class="severity ${sev(a.severity)}">${esc(a.severity)}</span></td>
      <td class="mono">${esc(time(a.timestamp))}</td><td>${esc(title)}</td>
      <td>${esc(a.host || a.event?.host || '—')}</td><td><span class="tag">DETECTED</span></td>
      <td><button class="analyze" data-analyze="${esc(a.alert_id)}">✦ Analyze</button></td></tr>`;
  }).join('') : '<tr><td colspan="6" class="empty">No alerts found</td></tr>';
}
function renderOverview() {
  const counts = {critical:0,high:0,medium:0,low:0,info:0};
  alerts.forEach(a => { const s=sev(a.severity); counts[s==='informational'?'info':s]=(counts[s==='informational'?'info':s]||0)+1; });
  const max = Math.max(1,...Object.values(counts));
  $('severity-bars').innerHTML = Object.entries(counts).map(([s,n]) => `<div class="sev-row"><span>${s.toUpperCase()}</span><div class="bar"><i style="width:${n/max*100}%;background:${({critical:'#ff5f68',high:'#ffb45c',medium:'#e8d477',low:'#48d9a0',info:'#69aee9'})[s]}"></i></div><b>${n}</b></div>`).join('');
  const latest = alerts.slice(0,5);
  $('recent-alerts').innerHTML = latest.length ? latest.map(a => `<div class="alert-item">
    <i class="dot" style="background:${sev(a.severity)==='critical'?'#ff5f68':sev(a.severity)==='high'?'#ffb45c':'#48d9d0'}"></i>
    <div><strong>${esc(a.rule?.title || a.title || 'Security alert')}</strong><small>${esc(a.host || 'Unknown host')} · ${esc(a.severity)}</small></div>
    <time>${esc(time(a.timestamp))}</time></div>`).join('') : '<div class="empty">No alerts received yet</div>';
}

function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('hidden', p.id !== name));
  document.querySelectorAll('.nav').forEach(b => b.classList.toggle('active', b.dataset.page === name));
  const titles = {overview:['OVERVIEW','Security Overview'],raw:['RAW LOGS','Raw Log Stream'],normalized:['NORMALIZED EVENTS','Normalized Events'],alerts:['SECURITY ALERTS','Security Alerts']};
  $('page-label').textContent=titles[name][0]; $('page-title').textContent=titles[name][1];
}
function toast(text) {
  $('toast').textContent=text; $('toast').classList.remove('hidden');
  clearTimeout(window.toastTimer); window.toastTimer=setTimeout(()=>$('toast').classList.add('hidden'),3500);
}
function reportValue(value) {
  if (Array.isArray(value)) return value.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join('\n');
  if (value && typeof value === 'object') return JSON.stringify(value,null,2);
  return value == null || value === '' ? 'Not provided by analysis' : String(value);
}
function reportSection(title, value) {
  if (value == null || value === '' || (Array.isArray(value) && !value.length)) return '';
  const items = Array.isArray(value) ? `<ul>${value.map(v=>`<li>${esc(typeof v==='object'?JSON.stringify(v):v)}</li>`).join('')}</ul>` : `<p>${esc(reportValue(value))}</p>`;
  return `<section class="report-section"><h3>${esc(title)}</h3>${items}</section>`;
}

function displayReport(data, fallbackTitle) {
  $('report-title').textContent = fallbackTitle || 'Incident Analysis';
  const verdict = data.verdict || 'INCONCLUSIVE';
  $('report-content').innerHTML = `
    <div class="report-verdict">${esc(verdict)} · ${esc(data.severity || 'UNSPECIFIED')} · Confidence: ${esc(data.confidence ?? 'N/A')}</div>
    ${reportSection('Executive Summary',data.executive_summary)}
    ${reportSection('Root Cause',data.root_cause)}
    ${reportSection('Attack Timeline',data.attack_timeline)}
    ${reportSection('MITRE ATT&CK',data.mitre_attack)}
    ${reportSection('Affected Entities',data.affected_entities)}
    ${reportSection('Recommended Actions',data.recommended_actions)}
    ${reportSection('Analysis Timestamp',data.analyzed_at)}
    <p class="eyebrow">INCIDENT ID: ${esc(data.incident_id || '—')}</p>`;
  $('report-modal').classList.remove('hidden');
}

async function sendForAnalysis(url, options, button, title) {
  $('report-title').textContent = title || 'Incident Analysis';
  $('report-content').innerHTML = '<div class="empty">AgenticSOC is analyzing the selected event. This may take a minute...</div>';
  $('report-modal').classList.remove('hidden');

  if (button) {
    button.disabled = true;
    button.textContent = 'Analyzing...';
  }

  try {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Analysis failed (${response.status})`);
    displayReport(data, title);
  } catch (error) {
    $('report-content').innerHTML = `<div class="empty">Analysis failed: ${esc(error.message)}</div>`;
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = '✦ Analyze';
    }
  }
}

function analyzeAlert(id, button) {
  const alert = alerts.find(a => String(a.alert_id) === String(id));
  return sendForAnalysis(
    `${API}/api/alerts/${encodeURIComponent(id)}/analyze`,
    {method:'POST'},
    button,
    alert?.rule?.title || 'Incident Analysis'
  );
}

function analyzeLog(type, index, button) {
  const collection = type === 'raw' ? rawLogs : normalizedLogs;
  const event = collection[index];
  if (!event) return toast('Log event not found. Refresh and try again.');

  return sendForAnalysis(
    `${API}/api/logs/analyze`,
    {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({log_type:type, event})
    },
    button,
    `${type === 'raw' ? 'Raw' : 'Normalized'} Log Investigation`
  );
}

document.querySelectorAll('.nav').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.page)));
document.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.goto)));
$('refresh').addEventListener('click',refreshData);
$('raw-search').addEventListener('input',renderRaw);
$('normalized-search').addEventListener('input',renderNormalized);
$('alert-search').addEventListener('input',renderAlerts);

['raw-table', 'normalized-table'].forEach(tableId => {
  $(tableId).addEventListener('click', e => {
    const button = e.target.closest('[data-log-type]');
    if (button) analyzeLog(button.dataset.logType, Number(button.dataset.logIndex), button);
  });
});

$('alerts-table').addEventListener('click',e=>{
  const button=e.target.closest('[data-analyze]');
  if(button) analyzeAlert(button.dataset.analyze,button);
});
$('close-report').addEventListener('click',()=>$('report-modal').classList.add('hidden'));
$('report-modal').addEventListener('click',e=>{if(e.target.id==='report-modal') $('report-modal').classList.add('hidden');});
document.addEventListener('keydown',e=>{if(e.key==='Escape') $('report-modal').classList.add('hidden');});
function clock(){ $('clock').textContent=new Date().toLocaleTimeString(); }
clock(); setInterval(clock,1000);
refreshData(); setInterval(refreshData,5000);
