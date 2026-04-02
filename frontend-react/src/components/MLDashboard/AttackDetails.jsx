import React from 'react';
import { AlertTriangle, Info, ShieldX } from 'lucide-react';

const AttackDetails = () => {
  // Static for now, but can be linked to prediction table clicks
  return (
    <div className="hidden fixed bottom-10 right-10 w-96 glass-panel p-6 shadow-2xl border-danger/30 animate-in fade-in slide-in-from-bottom-5 duration-500">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-10 h-10 rounded-full bg-danger/20 flex items-center justify-center text-danger">
          <AlertTriangle size={24} />
        </div>
        <div>
          <h3 className="text-white font-bold tracking-tight">Anomalous Activity Detected</h3>
          <p className="text-[10px] text-danger font-bold uppercase tracking-widest">Immediate Block Triggered</p>
        </div>
      </div>
      
      <div className="space-y-4">
        <div className="bg-black/20 rounded-lg p-3 border border-white/5">
          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-widest block mb-1">Attack Vector</span>
          <span className="text-sm text-white font-semibold">DDoS / SYN Flood</span>
        </div>
        
        <div className="space-y-2">
          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-widest block mb-1">Root Cause Analysis</span>
          <div className="flex items-start gap-3 text-xs text-gray-400">
            <Info size={14} className="text-primary mt-0.5 shrink-0" />
            <span>High density of short-duration flows from a single source IP.</span>
          </div>
          <div className="flex items-start gap-3 text-xs text-gray-400">
            <Info size={14} className="text-primary mt-0.5 shrink-0" />
            <span>Abnormal ratio of outgoing to incoming packets detected.</span>
          </div>
        </div>

        <button className="w-full py-2 bg-danger/20 hover:bg-danger/30 text-danger border border-danger/30 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-2">
          <ShieldX size={14} />
          View IPTables Rule
        </button>
      </div>
    </div>
  );
};

export default AttackDetails;
