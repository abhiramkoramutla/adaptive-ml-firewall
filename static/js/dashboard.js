let trafficData = {
    labels: [],
    datasets: [{
        label: 'Packets/s',
        data: [],
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        fill: true,
        tension: 0.4,
        borderWidth: 3,
        pointRadius: 0,
        pointHoverRadius: 6,
        pointBackgroundColor: '#3b82f6',
        pointBorderColor: '#fff',
        pointBorderWidth: 2,
        shadowBlur: 15,
        shadowColor: 'rgba(59, 130, 246, 0.5)'
    }]
};

function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    
    // Create gradient
    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
    gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
    trafficData.datasets[0].backgroundColor = gradient;

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: trafficData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(15, 23, 42, 0.9)',
                    titleColor: '#94a3b8',
                    bodyColor: '#fff',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false
                }
            },
            scales: {
                x: {
                    display: false,
                    grid: { display: false }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.03)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#64748b',
                        font: { size: 10, weight: '500' },
                        padding: 10,
                        callback: function(value) { return value + ' pkt/s' }
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'nearest'
            },
            animation: { duration: 1000, easing: 'easeOutQuart' }
        },
        plugins: [{
            id: 'glow',
            beforeDraw: (chart) => {
                const ctx = chart.ctx;
                ctx.save();
                ctx.shadowBlur = 10;
                ctx.shadowColor = 'rgba(59, 130, 246, 0.4)';
            },
            afterDraw: (chart) => {
                chart.ctx.restore();
            }
        }]
    });
}

async function updateStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        
        document.getElementById('packets-stat').innerText = data.packets_inspected.toLocaleString();
        document.getElementById('threats-stat').innerText = data.threats_detected.toLocaleString();
        document.getElementById('blocked-stat').innerText = data.blocked_ips.toLocaleString();
        document.getElementById('confidence-stat').innerText = data.model_confidence.toFixed(2);
    } catch (e) {
        console.error("Error fetching status", e);
    }
}

async function updateTraffic() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        
        const rate = data.avg_packet_rate || 0;
        const now = new Date().toLocaleTimeString();
        
        // Add new data point
        trafficData.labels.push(now);
        trafficData.datasets[0].data.push(rate);
        
        // Keep last 30 points (approx 1 minute at 2s interval)
        if (trafficData.labels.length > 30) {
            trafficData.labels.shift();
            trafficData.datasets[0].data.shift();
        }
        
        trafficChart.update('none'); // Update without full animation for smoothness

        // Also update active connections from /api/traffic
        const trafficRes = await fetch('/api/traffic');
        const trafficData_ = await trafficRes.json();
        document.getElementById('active-conns').innerText = trafficData_.active_connections;
        
    } catch (e) {
        console.error("Error fetching traffic", e);
    }
}

function getSeverityColor(confidence) {
    if (confidence > 0.8) return 'text-danger bg-danger/10 border-danger/20';
    if (confidence > 0.5) return 'text-warning bg-warning/10 border-warning/20';
    return 'text-primary bg-primary/10 border-primary/20';
}

function selectThreat(threatStr) {
    const threat = JSON.parse(decodeURIComponent(threatStr));
    const confidence = threat.confidence || threat.anomaly_score || 0;
    const detailsHtml = `
        <div class="w-full text-sm space-y-4">
            <div class="flex justify-between items-center pb-2 border-b border-gray-800">
                <span class="text-gray-400">Time</span>
                <span class="text-white font-medium">${new Date(threat.timestamp).toLocaleString()}</span>
            </div>
            <div class="flex justify-between items-center pb-2 border-b border-gray-800">
                <span class="text-gray-400">Source IP</span>
                <span class="text-danger font-mono bg-danger/10 px-2 py-0.5 rounded">${threat.src_ip || threat.source_ip}</span>
            </div>
            <div class="flex justify-between items-center pb-2 border-b border-gray-800">
                <span class="text-gray-400">Destination IP</span>
                <span class="text-white font-mono">${threat.dst_ip || threat.destination_ip}</span>
            </div>
            <div class="flex justify-between items-center pb-2 border-b border-gray-800">
                <span class="text-gray-400">Protocol</span>
                <span class="text-primary uppercase font-bold text-xs">${threat.protocol}</span>
            </div>
            <div class="flex justify-between items-center pb-2 border-b border-gray-800">
                <span class="text-gray-400">Classification</span>
                <span class="${getSeverityColor(confidence).split(' ')[0]} font-bold">
                    ${threat.attack_type}
                    ${threat.action === 'ALLOW' && (threat.src_ip === '127.0.0.1' || threat.source_ip === '127.0.0.1' || (threat.src_ip || threat.source_ip || '').startsWith('172.')) ? ' <span class="text-[10px] opacity-70">(Whitelisted)</span>' : ''}
                </span>
            </div>
            <div class="flex justify-between items-center pb-2 border-b border-gray-800">
                <span class="text-gray-400">ML Confidence Score</span>
                <span class="text-white font-mono text-lg">${confidence.toFixed(3)}</span>
            </div>
            <div class="flex justify-between items-center mt-2">
                <span class="text-gray-400">Action Taken</span>
                <span class="text-xs px-2 py-1 rounded-full ${threat.action === 'BLOCK' ? 'bg-danger/20 text-danger border border-danger/30' : 'bg-success/20 text-success border border-success/30'} font-bold">
                    ${threat.action}
                </span>
            </div>
        </div>
    `;
    document.getElementById('attack-details').innerHTML = detailsHtml;
}

// Attach a global reference for the onclick handler
window.selectThreat = selectThreat;

async function updateThreats() {
    try {
        const res = await fetch('/api/threats');
        const data = await res.json();
        
        let html = '';
        data.forEach(threat => {
            const time = new Date(threat.timestamp).toLocaleTimeString();
            const actionClass = threat.action === 'BLOCK' ? 'text-danger' : 'text-success';
            const threatObjStr = encodeURIComponent(JSON.stringify(threat));
            const confidence = threat.confidence || threat.anomaly_score || 0;
            const src_ip = threat.src_ip || threat.source_ip;
            const displayAttackType = threat.attack_type === 'None' ? 'Anomaly' : threat.attack_type;
            
            html += `
                <tr class="hover:bg-gray-800/50 cursor-pointer transition border-b border-gray-800/50" onclick="selectThreat('${threatObjStr}')">
                    <td class="px-6 py-4 text-gray-400">${time}</td>
                    <td class="px-6 py-4 font-mono text-gray-300">${src_ip}</td>
                    <td class="px-6 py-4"><span class="px-2 py-1 text-xs rounded-full ${getSeverityColor(confidence)}">${displayAttackType}</span></td>
                    <td class="px-6 py-4 text-gray-400 font-mono">${confidence.toFixed(2)}</td>
                    <td class="px-6 py-4 font-semibold ${actionClass}">${threat.action}</td>
                </tr>
            `;
        });
        
        document.getElementById('threats-table-body').innerHTML = html;
        
    } catch (e) {
        console.error("Error fetching threats", e);
    }
}

async function unblockIp(ip) {
    if(!confirm(`Are you sure you want to unblock ${ip}?`)) return;
    
    try {
        const res = await fetch('/api/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if(data.success) {
            alert(data.message);
            updateBlockedIps();
            updateStatus();
        } else {
            alert("Error: " + data.error);
        }
    } catch (e) {
        alert("Failed to unblock IP: " + e);
    }
}

// Expose to window
window.unblockIp = unblockIp;

async function updateBlockedIps() {
    try {
        const res = await fetch('/api/blocked_ips');
        const data = await res.json();
        
        let html = '';
        data.forEach(block => {
            const time = new Date(block.block_time).toLocaleString();
            html += `
                <tr class="hover:bg-gray-800/50 transition border-b border-gray-800/50 group">
                    <td class="px-6 py-4 font-mono text-danger font-medium">${block.ip}</td>
                    <td class="px-6 py-4 text-gray-400 text-sm whitespace-normal">${time}</td>
                    <td class="px-6 py-4 text-gray-300">
                        <div class="flex flex-col whitespace-normal">
                            <span class="text-xs text-warning mb-1 font-bold">${block.attack_type}</span>
                            <span class="text-xs text-gray-500 font-mono">${block.reason}</span>
                        </div>
                    </td>
                    <td class="px-6 py-4 text-right">
                        <button onclick="unblockIp('${block.ip}')" class="px-3 py-1.5 bg-surface border border-gray-700 hover:border-success/50 hover:bg-success/10 text-gray-300 hover:text-success rounded-lg text-xs font-medium transition-all shadow-sm">
                            Unblock
                        </button>
                    </td>
                </tr>
            `;
        });
        
        document.getElementById('blocked-table-body').innerHTML = html;
        
    } catch (e) {
        console.error("Error fetching blocked IPs", e);
    }
}


document.addEventListener('DOMContentLoaded', () => {
    initChart();
    
    updateStatus();
    updateTraffic();
    updateThreats();
    updateBlockedIps();
    
    setInterval(() => {
        updateStatus();
        updateTraffic();
        updateThreats();
        updateBlockedIps();
    }, 2000);
});
