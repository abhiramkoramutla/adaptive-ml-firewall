/* ── script.js — Adaptive ML Firewall Dashboard ─────────── */

const API = "/api/stats";
const POLL_INTERVAL = 2000;   // ms

// ── Clock ────────────────────────────────────────────────
function updateClock() {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString("en-US", {hour12: false});
}
setInterval(updateClock, 1000);
updateClock();

// ── Chart.js defaults ────────────────────────────────────
Chart.defaults.color = "#5a7095";
Chart.defaults.font.family = "'Segoe UI', sans-serif";

const chartDefaults = {
  responsive: true,
  maintainAspectRatio: true,
  plugins: { legend: { display: false } },
  scales: {
    x: { grid: { color: "#1a2a4520" }, ticks: { color: "#5a7095", maxTicksLimit: 8 } },
    y: { grid: { color: "#1a2a4520" }, ticks: { color: "#5a7095" }, beginAtZero: true }
  }
};

// ── Anomaly Rate Chart (line) ─────────────────────────────
const anomalyLabels = [];
const anomalyData   = [];
const anomalyCtx    = document.getElementById("anomalyRateChart").getContext("2d");
const anomalyChart  = new Chart(anomalyCtx, {
  type: "line",
  data: {
    labels: anomalyLabels,
    datasets: [{
      data: anomalyData,
      borderColor: "#00e5ff",
      backgroundColor: "rgba(0,229,255,0.08)",
      borderWidth: 2,
      pointRadius: 2,
      tension: 0.4,
      fill: true,
    }]
  },
  options: {
    ...chartDefaults,
    scales: {
      x: { ...chartDefaults.scales.x },
      y: { ...chartDefaults.scales.y, max: 100, ticks: { color: "#5a7095", callback: v => v + "%" } }
    }
  }
});

// ── Traffic Distribution Chart (doughnut) ─────────────────
const distCtx   = document.getElementById("trafficDistChart").getContext("2d");
const distChart = new Chart(distCtx, {
  type: "doughnut",
  data: {
    labels: ["Normal", "Anomaly", "Blocked"],
    datasets: [{
      data: [1, 0, 0],
      backgroundColor: ["rgba(0,230,118,0.7)", "rgba(255,145,0,0.7)", "rgba(255,23,68,0.7)"],
      borderColor:     ["#00e676", "#ff9100", "#ff1744"],
      borderWidth: 1,
      hoverOffset: 4,
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: true,
    cutout: "65%",
    plugins: {
      legend: {
        display: true,
        position: "bottom",
        labels: { color: "#5a7095", boxWidth: 10, font: { size: 11 } }
      }
    }
  }
});

// ── Packet Volume Chart (bar) ─────────────────────────────
const volLabels = [];
const volData   = [];
const volCtx    = document.getElementById("packetVolumeChart").getContext("2d");
const volChart  = new Chart(volCtx, {
  type: "bar",
  data: {
    labels: volLabels,
    datasets: [{
      data: volData,
      backgroundColor: "rgba(41,121,255,0.5)",
      borderColor: "#2979ff",
      borderWidth: 1,
      borderRadius: 3,
    }]
  },
  options: {
    ...chartDefaults,
    barPercentage: 0.7,
  }
});

// ── Rolling window helpers ────────────────────────────────
const MAX_POINTS = 30;
let prevTotalPackets = 0;
let lastUpdate = null;

function pushPoint(chart, labels, data, label, value) {
  labels.push(label);
  data.push(value);
  if (labels.length > MAX_POINTS) { labels.shift(); data.shift(); }
  chart.update("none");
}

// ── Update stat cards ─────────────────────────────────────
function setCard(id, value) {
  const el = document.getElementById(id);
  if (el && el.textContent !== String(value)) {
    el.textContent = value;
    el.classList.add("flash");
    setTimeout(() => el.classList.remove("flash"), 400);
  }
}

// ── Render event feed ─────────────────────────────────────
function renderEvents(events) {
  const list = document.getElementById("eventsList");
  const countEl = document.getElementById("eventCount");
  if (!events || events.length === 0) return;

  countEl.textContent = events.length + " events";
  list.innerHTML = events.map(ev => {
    const cls = ev.status === "BLOCKED" ? "blocked" : ev.status === "ANOMALY" ? "anomaly" : "normal";
    return `<div class="event-item ${cls}">
      <span class="event-time">${ev.time}</span>
      <span class="event-ip">${ev.ip}</span>
      <span class="event-score">score: ${ev.score}</span>
      <span class="event-status">${ev.status}</span>
    </div>`;
  }).join("");
}

// ── Render blocked IPs list ───────────────────────────────
function renderBlocked(ips) {
  const list = document.getElementById("blockedList");
  if (!ips || ips.length === 0) {
    list.innerHTML = '<div class="event-placeholder">No IPs currently blocked.</div>';
    return;
  }
  list.innerHTML = ips.map(ip =>
    `<div class="blocked-item">
      <span class="blocked-ip">⛔ ${ip}</span>
      <button class="btn-unblock" onclick="confirmUnblock('${ip}')">Unblock</button>
    </div>`
  ).join("");
}

// ── Fetch and update everything ───────────────────────────
async function fetchStats() {
  try {
    const res = await fetch(API);
    if (!res.ok) return;
    const d = await res.json();

    const now = new Date().toLocaleTimeString("en-US", {hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit"});

    // Stat cards
    setCard("totalPackets",       d.total_packets.toLocaleString());
    setCard("anomaliesDetected",  d.anomalies_detected.toLocaleString());
    setCard("blockedCount",       d.blocked_count);
    setCard("detectionRate",      d.detection_rate + "%");

    // Anomaly rate chart
    pushPoint(anomalyChart, anomalyLabels, anomalyData, now, d.live_anomaly_rate);

    // Packet volume delta
    const delta = d.total_packets - prevTotalPackets;
    prevTotalPackets = d.total_packets;
    pushPoint(volChart, volLabels, volData, now, Math.max(delta, 0));

    // Distribution chart
    const normal   = d.total_packets - d.anomalies_detected;
    const anomaly  = d.anomalies_detected - d.blocked_count;
    const blocked  = d.blocked_count;
    distChart.data.datasets[0].data = [
      Math.max(normal, 0),
      Math.max(anomaly, 0),
      Math.max(blocked, 0),
    ];
    distChart.update("none");

    // Events and blocked list
    renderEvents(d.recent_events);
    renderBlocked(d.blocked_ips);

    lastUpdate = now;
  } catch (err) {
    console.warn("Stats fetch failed:", err);
  }
}

// ── Unblock modal ─────────────────────────────────────────
let pendingUnblockIp = null;

function confirmUnblock(ip) {
  pendingUnblockIp = ip;
  document.getElementById("modalIp").textContent = ip;
  document.getElementById("unblockModal").style.display = "flex";
}

function closeModal() {
  document.getElementById("unblockModal").style.display = "none";
  pendingUnblockIp = null;
}

document.getElementById("confirmUnblock").addEventListener("click", async () => {
  if (!pendingUnblockIp) return;
  try {
    const res = await fetch("/api/unblock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: pendingUnblockIp }),
    });
    const data = await res.json();
    if (data.success) {
      console.log(`Unblocked: ${pendingUnblockIp}`);
    }
  } catch (e) {
    console.error("Unblock failed:", e);
  }
  closeModal();
  fetchStats();
});

// ── Flash animation style (injected) ─────────────────────
const style = document.createElement("style");
style.textContent = `
  .flash { animation: numFlash 0.4s ease; }
  @keyframes numFlash {
    0%  { color: #00e5ff; }
    100%{ color: inherit; }
  }
`;
document.head.appendChild(style);

// ── Start polling ─────────────────────────────────────────
fetchStats();
setInterval(fetchStats, POLL_INTERVAL);
