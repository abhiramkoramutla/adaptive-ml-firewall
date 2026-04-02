import React, { useState, useEffect } from 'react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  ReferenceLine 
} from 'recharts';
import axios from 'axios';

const AnomalyChart = ({ fullWidth = false }) => {
  const [data, setData] = useState([]);
  const [threshold, setThreshold] = useState(0.65);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('/api/anomaly-distribution');
        setData(response.data.data);
        setThreshold(response.data.threshold);
      } catch (error) {
        console.error("Error fetching anomaly distribution:", error);
      }
    };
    fetchData();
  }, []);

  return (
    <div className={`h-full min-h-[350px] ${fullWidth ? 'glass-panel p-8' : ''}`}>
      {fullWidth && (
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-white mb-2 italic tracking-tight">Real-time Threat Probability Distribution</h2>
          <p className="text-gray-500 text-xs uppercase tracking-[0.3em] font-medium">Deep Neural Analysis of Network Flows</p>
        </div>
      )}
      <ResponsiveContainer width="100%" height={fullWidth ? 450 : 350}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10b981" stopOpacity={0.6}/>
              <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
            </linearGradient>
            <linearGradient id="colorAnomaly" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6}/>
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" vertical={false} />
          <XAxis 
            dataKey="score" 
            stroke="#718096" 
            fontSize={10} 
            label={{ value: 'Anomaly Score (0 - 1)', position: 'insideBottom', offset: -5, fontSize: 10, fill: '#718096' }}
          />
          <YAxis stroke="#718096" fontSize={10} />
          <Tooltip
            contentStyle={{ 
              backgroundColor: 'rgba(15, 23, 42, 0.95)', 
              border: '1px solid rgba(255,255,255,0.1)', 
              borderRadius: '12px',
              backdropFilter: 'blur(10px)',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
            }}
            itemStyle={{ fontSize: '11px', fontWeight: 'bold' }}
          />
          <ReferenceLine 
            x={threshold} 
            stroke="#ef4444" 
            strokeDasharray="5 5" 
            label={{ 
              value: 'Block Threshold', 
              position: 'top', 
              fill: '#ef4444', 
              fontSize: 10,
              fontWeight: 'bold'
            }} 
          />
          <Area 
            type="monotone" 
            dataKey="normal" 
            stroke="#10b981" 
            fillOpacity={1} 
            fill="url(#colorNormal)" 
            name="Normal Flow Density"
          />
          <Area 
            type="monotone" 
            dataKey="anomaly" 
            stroke="#ef4444" 
            fillOpacity={1} 
            fill="url(#colorAnomaly)" 
            name="Attack Flow Density"
          />
        </AreaChart>
      </ResponsiveContainer>
      {fullWidth && (
        <div className="mt-8 border-t border-white/5 pt-6 text-gray-400 text-sm leading-relaxed">
          The <strong>Isolation Forest</strong> algorithm assigns scores based on how easily a flow can be isolated. 
          Normal traffic forms a high-density cluster (green) near low scores, while malicious intrusions (red) deviate 
          into higher isolation scores. Any flow crossing the <span className="text-danger font-bold">{threshold} threshold</span> is 
          immediately intercepted and dropped.
        </div>
      )}
    </div>
  );
};

export default AnomalyChart;
