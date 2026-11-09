import React, { useState, useEffect } from 'react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  AreaChart, 
  Area 
} from 'recharts';
import axios from 'axios';

const RocCurve = () => {
  const [data, setData] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('/api/roc-curve');
        setData(response.data);
      } catch (error) {
        console.error("Error fetching ROC data:", error);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="glass-panel p-8 h-full min-h-[500px] flex flex-col">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <div className="w-1 h-6 bg-blue-500 rounded-full"></div>
            ROC Curve (Receiver Operating Characteristic)
          </h2>
          <p className="text-xs text-gray-500 mt-1 uppercase tracking-widest">Visualizing True Positive Rate vs False Positive Rate</p>
        </div>
        <div className="flex flex-col items-end">
          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">Current AUC</span>
          <span className="text-3xl font-black text-blue-400">0.962</span>
        </div>
      </div>

      <div className="w-full" style={{ height: '380px' }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorTpr" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.6}/>
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" vertical={false} />
            <XAxis 
              dataKey="fpr" 
              stroke="#718096" 
              fontSize={10} 
              tickFormatter={(val) => val.toFixed(1)}
              label={{ value: 'False Positive Rate', position: 'insideBottom', offset: -5, fontSize: 10, fill: '#718096' }}
            />
            <YAxis 
              stroke="#718096" 
              fontSize={10}
              label={{ value: 'True Positive Rate', angle: -90, position: 'insideLeft', fontSize: 10, fill: '#718096' }}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'rgba(15, 23, 42, 0.95)', 
                border: '1px solid rgba(255,255,255,0.1)', 
                borderRadius: '12px',
                backdropFilter: 'blur(10px)',
                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
              }}
              labelStyle={{ color: '#fff', fontWeight: 'bold' }}
              itemStyle={{ color: '#3b82f6', fontSize: '11px' }}
              formatter={(value) => [value.toFixed(3), 'Rate']}
            />
            {/* Reference diagonal line */}
            <Line type="monotone" dataKey={(val) => val.fpr} stroke="#4a5568" strokeDasharray="5 5" dot={false} strokeWidth={1} />
            <Area 
              type="monotone" 
              dataKey="tpr" 
              stroke="#3b82f6" 
              strokeWidth={3}
              fillOpacity={1} 
              fill="url(#colorTpr)" 
              animationDuration={2000}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-4 bg-white/5 rounded-lg border border-white/5">
          <h4 className="text-xs font-bold text-blue-400 uppercase tracking-widest mb-2">High Efficiency</h4>
          <p className="text-gray-400 text-xs">A curve that hugs the top-left corner indicates a high TPR with minimal FPR, showing superior detection power.</p>
        </div>
        <div className="p-4 bg-white/5 rounded-lg border border-white/5">
          <h4 className="text-xs font-bold text-blue-400 uppercase tracking-widest mb-2">Threshold Choice</h4>
          <p className="text-gray-400 text-xs">Our firewall operates at the optimal "elbow" point, balancing maximum intrusion discovery against packet loss.</p>
        </div>
        <div className="p-4 bg-white/5 rounded-lg border border-white/5">
          <h4 className="text-xs font-bold text-blue-400 uppercase tracking-widest mb-2">AUC Logic</h4>
          <p className="text-gray-400 text-xs">An AUC of 0.962 means there is a 96.2% chance that the model will distinguish a random attack from a normal packet.</p>
        </div>
      </div>
    </div>
  );
};

export default RocCurve;
