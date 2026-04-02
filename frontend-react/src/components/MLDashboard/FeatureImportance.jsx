import React, { useState, useEffect } from 'react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  Cell 
} from 'recharts';
import axios from 'axios';

const FeatureImportance = ({ fullWidth = false }) => {
  const [data, setData] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('/api/feature-importance');
        setData(response.data);
      } catch (error) {
        console.error("Error fetching feature importance:", error);
      }
    };
    fetchData();
  }, []);

  const COLORS = ['#3b82f6', '#60a5fa', '#93c5fd', '#10b981', '#34d399', '#6ee7b7', '#f59e0b', '#fbbf24', '#fcd34d', '#ef4444'];

  return (
    <div className={`h-full min-h-[350px] ${fullWidth ? 'glass-panel p-8' : ''}`}>
      {fullWidth && (
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-white mb-2 italic tracking-tight">Security Feature Hierarchy</h2>
          <p className="text-gray-500 text-sm uppercase tracking-widest">Identifying the strongest predictive signals</p>
        </div>
      )}
      <ResponsiveContainer width="100%" height={fullWidth ? 450 : 350}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" horizontal={false} />
          <XAxis type="number" stroke="#718096" fontSize={10} axisLine={false} tickLine={false} />
          <YAxis 
            dataKey="feature" 
            type="category" 
            stroke="#e2e8f0" 
            fontSize={12} 
            fontFamily="monospace"
            axisLine={false}
            tickLine={false}
            width={120}
          />
          <Tooltip
            contentStyle={{ 
              backgroundColor: 'rgba(15, 23, 42, 0.95)', 
              border: '1px solid rgba(255,255,255,0.1)', 
              borderRadius: '12px',
              backdropFilter: 'blur(10px)',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
            }}
            cursor={{ fill: 'rgba(255,255,255,0.05)' }}
            itemStyle={{ fontSize: '11px', fontWeight: 'bold' }}
            formatter={(value) => [value, 'Weight']}
          />
          <Bar dataKey="importance" radius={[0, 4, 4, 0]} animationDuration={1500}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default FeatureImportance;
