const rawLogs = [
  { time: "12:10:48", source: "auth", host: "tacticalpi", message: "Accepted publickey for tacticalhavoc from 10.79.241.15 port 42812 ssh2" },
  { time: "12:10:32", source: "syslog", host: "tacticalpi", message: "systemd[1]: Started Session 184 of User tacticalhavoc." },
  { time: "12:10:16", source: "kernel", host: "tacticalpi", message: "kernel: [UFW BLOCK] IN=wlan0 OUT= MAC= SRC=10.79.241.77 DST=10.79.241.199" },
  { time: "12:09:54", source: "auth", host: "tacticalpi", message: "Failed password for invalid user admin from 10.79.241.83 port 51422 ssh2" },
  { time: "12:09:41", source: "syslog", host: "tacticalpi", message: "filebeat[1324]: Published event to Kafka topic siem.raw" },
  { time: "12:09:22", source: "auth", host: "tacticalpi", message: "session opened for user tacticalhavoc(uid=1000) by (uid=0)" },
  { time: "12:08:57", source: "kernel", host: "tacticalpi", message: "kernel: audit: type=1400 apparmor=DENIED operation=open profile=/usr/sbin/sshd" },
  { time: "12:08:31", source: "syslog", host: "tacticalpi", message: "CRON[1832]: (root) CMD (/usr/lib/sysstat/sa1 1 1)" }
];

const normalizedLogs = [
  { time: "12:10:48", type: "authentication", severity: "info", host: "tacticalpi", message: "Successful SSH public-key authentication", source: "auth" },
  { time: "12:10:16", type: "network", severity: "medium", host: "tacticalpi", message: "Firewall blocked inbound connection", source: "kernel" },
  { time: "12:09:54", type: "authentication", severity: "high", host: "tacticalpi", message: "Failed SSH authentication for invalid user admin", source: "auth" },
  { time: "12:09:41", type: "system", severity: "info", host: "tacticalpi", message: "Filebeat published event to Kafka", source: "syslog" },
  { time: "12:08:57", type: "system", severity: "medium", host: "tacticalpi", message: "AppArmor denied file operation", source: "kernel" },
  { time: "12:08:22", type: "process", severity: "low", host: "tacticalpi", message: "Scheduled system statistics task executed", source: "syslog" },
  { time: "12:07:49", type: "authentication", severity: "high", host: "tacticalpi", message: "Multiple failed authentication attempts detected", source: "auth" },
  { time: "12:07:12", type: "network", severity: "info", host: "tacticalpi", message: "Network interface state changed", source: "syslog" }
];

const alerts = [
  { level: "critical", time: "12:06:41", title: "Potential brute-force SSH activity", host: "tacticalpi", desc: "18 failed authentication attempts from 10.79.241.83 within 90 seconds.", status: "Open" },
  { level: "high", time: "12:04:18", title: "Invalid user authentication attempt", host: "tacticalpi", desc: "SSH login attempted using a non-existent privileged account.", status: "Investigating" },
  { level: "high", time: "11:58:02", title: "Repeated firewall blocks", host: "tacticalpi", desc: "Multiple inbound connections blocked by host firewall.", status: "Open" },
  { level: "medium", time: "11:52:37", title: "AppArmor denial", host: "tacticalpi", desc: "Application attempted an operation outside its security profile.", status: "Resolved" },
  { level: "medium", time: "11:47:13", title: "Unusual authentication pattern", host: "tacticalpi", desc: "Authentication frequency exceeded the configured baseline.", status: "Investigating" },
  { level: "low", time: "11:42:51", title: "New SSH session", host: "tacticalpi", desc: "New interactive session opened for an existing user.", status: "Resolved" }
];

function severityBadge(severity) {
  return `<span class="severity-badge badge-${severity}">${severity}</span>`;
}

function renderRawLogs() {
  const search = (document.getElementById("rawSearch")?.value || "").toLowerCase();
  const source = document.getElementById("rawSource")?.value || "";
  const rows = rawLogs.filter(log =>
    (!search || `${log.time} ${log.source} ${log.host} ${log.message}`.toLowerCase().includes(search)) &&
    (!source || log.source === source)
  );

  document.getElementById("rawTable").innerHTML = rows.map(log => `
    <tr>
      <td class="mono">${log.time}</td>
      <td>${log.source}</td>
      <td>${log.host}</td>
      <td class="message mono">${escapeHtml(log.message)}</td>
    </tr>
  `).join("");
}

function renderNormalizedLogs() {
  const search = (document.getElementById("normalizedSearch")?.value || "").toLowerCase();
  const severity = document.getElementById("severityFilter")?.value || "";
  const type = document.getElementById("eventTypeFilter")?.value || "";

  const rows = normalizedLogs.filter(log =>
    (!search || `${log.time} ${log.type} ${log.severity} ${log.host} ${log.message}`.toLowerCase().includes(search)) &&
    (!severity || log.severity === severity) &&
    (!type || log.type === type)
  );

  document.getElementById("normalizedTable").innerHTML = rows.map(log => `
    <tr>
      <td class="mono">${log.time}</td>
      <td class="event-type">${log.type}</td>
      <td>${severityBadge(log.severity)}</td>
      <td>${log.host}</td>
      <td>${escapeHtml(log.message)}</td>
    </tr>
  `).join("");
}

function renderAlerts(targetId) {
  const target = document.getElementById(targetId);
  if (!target) return;

  if (targetId === "overview-alerts") {
    target.innerHTML = alerts.slice(0, 5).map(alert => `
      <div class="alert-row">
        <span class="alert-level level-${alert.level}"></span>
        <span class="alert-time">${alert.time}</span>
        <span class="alert-name">${alert.title}</span>
        <span class="alert-host">${alert.host}</span>
      </div>
    `).join("");
  } else {
    target.innerHTML = alerts.map(alert => `
      <div class="alert-card">
        <span class="alert-level level-${alert.level}"></span>
        <div>${severityBadge(alert.level)}</div>
        <div>
          <div class="alert-title">${alert.title}</div>
          <div class="alert-desc">${alert.desc}</div>
        </div>
        <div>
          <div class="alert-time">${alert.time}</div>
          <div class="status status-${alert.status.toLowerCase()}">${alert.status}</div>
        </div>
      </div>
    `).join("");
  }
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[char]));
}

function showPage(pageName) {
  document.querySelectorAll(".page").forEach(page => page.classList.remove("active-page"));
  document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));

  const page = document.getElementById(pageName);
  const nav = document.querySelector(`.nav-item[data-page="${pageName}"]`);
  if (page) page.classList.add("active-page");
  if (nav) nav.classList.add("active");

  const titles = {
    overview: "Overview",
    raw: "Raw Logs",
    normalized: "Normalized Logs",
    alerts: "Alerts"
  };
  document.getElementById("page-title").textContent = titles[pageName] || "Overview";
}

function updateClock() {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString("en-GB");
}

function drawChart() {
  const canvas = document.getElementById("eventChart");
  if (!canvas) return;

  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;

  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = rect.height;
  const pad = { left: 8, right: 5, top: 12, bottom: 24 };

  const values = [260, 285, 250, 310, 338, 330, 365, 402, 385, 430, 468, 445, 492, 515, 486, 530, 560, 548, 590, 610, 578, 625, 642, 618, 670, 688, 655, 704, 690, 725, 710, 748, 770, 752, 790, 815, 802, 835, 824, 860, 842, 880, 895, 870, 914, 902, 936, 950, 925, 962, 978, 965, 1002, 988, 1020, 1008, 1045, 1030, 1062, 1080];
  const max = Math.max(...values);
  const min = Math.min(...values);
  const chartW = w - pad.left - pad.right;
  const chartH = h - pad.top - pad.bottom;

  ctx.strokeStyle = "#1c2530";
  ctx.lineWidth = 1;

  for (let i = 0; i < 4; i++) {
    const y = pad.top + (chartH / 3) * i;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(w - pad.right, y);
    ctx.stroke();
  }

  ctx.beginPath();
  values.forEach((value, i) => {
    const x = pad.left + (i / (values.length - 1)) * chartW;
    const y = pad.top + chartH - ((value - min) / (max - min)) * chartH;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#56a8ff";
  ctx.lineWidth = 1.5;
  ctx.stroke();

  const lastX = pad.left + chartW;
  const lastY = pad.top + chartH - ((values.at(-1) - min) / (max - min)) * chartH;
  ctx.fillStyle = "#56a8ff";
  ctx.beginPath();
  ctx.arc(lastX, lastY, 3, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#56616f";
  ctx.font = "9px Inter, sans-serif";
  ["60m", "45m", "30m", "15m", "now"].forEach((label, i) => {
    const x = pad.left + (i / 4) * chartW;
    ctx.fillText(label, x - (i === 4 ? 17 : 0), h - 5);
  });
}

document.querySelectorAll(".nav-item").forEach(button => {
  button.addEventListener("click", () => showPage(button.dataset.page));
});

document.querySelectorAll("[data-page-target]").forEach(button => {
  button.addEventListener("click", () => showPage(button.dataset.pageTarget));
});

document.getElementById("rawSearch").addEventListener("input", renderRawLogs);
document.getElementById("rawSource").addEventListener("change", renderRawLogs);
document.getElementById("normalizedSearch").addEventListener("input", renderNormalizedLogs);
document.getElementById("severityFilter").addEventListener("change", renderNormalizedLogs);
document.getElementById("eventTypeFilter").addEventListener("change", renderNormalizedLogs);

document.getElementById("refreshBtn").addEventListener("click", () => {
  renderRawLogs();
  renderNormalizedLogs();
  drawChart();
  document.getElementById("refreshBtn").style.transform = "rotate(360deg)";
  setTimeout(() => document.getElementById("refreshBtn").style.transform = "", 250);
});

window.addEventListener("resize", drawChart);

renderRawLogs();
renderNormalizedLogs();
renderAlerts("overview-alerts");
renderAlerts("alertsPage");
updateClock();
drawChart();
setInterval(updateClock, 1000);
