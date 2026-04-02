import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Terminal, ShieldCheck, ShieldAlert, AlertTriangle, Cpu } from 'lucide-react';

const PredictionTable = ({ fullHeight = false }) => {
  const [predictions, setPredictions] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('/api/live-predictions?n=30');
        setPredictions(response.data);
      } catch (error) {
        console.error("Error fetching predictions:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000); // Live update every 3 seconds
    return () => clearInterval(interval);
  }, []);

  if (loading) return (
    <div className="h-64 flex items-center justify-center text-gray-500 animate-pulse bg-white/5 rounded-xl">
      Connecting to real-time engine…
    </div>
  );

  return (
    <div className={`overflow-x-auto custom-scrollbar ${fullHeight ? 'glass-panel p-6 h-full' : ''}`}>
      {fullHeight && (
        <div className="mb-6 flex justify-between items-center">
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <Terminal className="text-success" size={24} />
            Live Inference Log
          </h2>
          <div className="flex gap-2">
             <div className="px-3 py-1 bg-success/10 text-success text-[10px] font-bold rounded-full border border-success/20">LIVE</div>
             <div className="px-3 py-1 bg-white/5 text-gray-400 text-[10px] font-bold rounded-full">5s Refresh</div>
          </div>
        </div>
      )}
      <table className="w-full text-left">
        <thead className="text-[10px] uppercase tracking-widest text-gray-500 border-b border-white/5">
          <tr>
            <th className="pb-4 font-bold">Timestamp</th>
            <th className="pb-4 font-bold">Source IP</th>
            <th className="pb-4 font-bold">Protocol</th>
            <th className="pb-4 font-bold">Size</th>
            <th className="pb-4 font-bold">Prediction</th>
            <th className="pb-4 font-bold text-right">Confidence</th>
          </tr>
        </thead>
        <tbody className="text-sm font-medium">
          {predictions.map((p, i) => (
            <tr key={i} className="border-b border-white/5 hover:bg-white/5 transition-colors group cursor-pointer">
              <td className="py-4 text-xs font-mono text-gray-400">{p.timestamp}</td>
              <td className="py-4 text-gray-200">
                <div className="flex items-center gap-2">
                  <Cpu size={14} className="text-gray-600" />
                  {p.source_ip}
                </div>
              </td>
              <td className="py-4">
                <span className="px-2 py-0.5 bg-white/5 rounded text-[10px] font-mono border border-white/10">{p.protocol}</span>
              </td>
              <td className="py-4 text-gray-500 text-xs">{p.packet_size ? `${Math.round(p.packet_size)} B` : '—'}</td>
              <td className="py-4">
                {p.prediction === 'Attack' ? (
                  <div className="flex items-center gap-2 text-danger">
                    <ShieldAlert size={14} />
                    <span className="font-bold underline decoration-danger/30 decoration-2 underline-offset-4">
                      {p.attack_type !== 'None' ? p.attack_type : 'Anomaly'}
                    </span>
                  </div>
                ) : p.prediction === 'Suspicious' ? (
                  <div className="flex items-center gap-2 text-yellow-400">
                    <AlertTriangle size={14} />
                    <span className="font-bold">
                      {p.attack_type !== 'None' ? p.attack_type : 'Suspicious'}
                    </span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-success">
                    <ShieldCheck size={14} />
                    <span>Normal</span>
                  </div>
                )}
              </td>
              <td className="py-4 text-right">
                <div className={`text-xs font-mono ${
                  p.prediction === 'Attack' ? 'text-danger' :
                  p.prediction === 'Suspicious' ? 'text-yellow-400' :
                  'text-success'
                }`}>
                  {(p.confidence_score * 100).toFixed(1)}%
                </div>
              </td>
            </tr>
          ))}
          {predictions.length === 0 && (
            <tr>
              <td colSpan={6} className="py-16 text-center text-gray-500 text-sm">
                No flows captured yet — start the firewall engine to see real-time data.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default PredictionTable;

