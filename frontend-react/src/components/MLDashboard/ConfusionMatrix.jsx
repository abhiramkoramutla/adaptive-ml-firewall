import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Info } from 'lucide-react';

const ConfusionMatrix = () => {
  const [data, setData] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('/api/confusion-matrix');
        setData(response.data);
      } catch (error) {
        console.error("Error fetching confusion matrix:", error);
      }
    };
    fetchData();
  }, []);

  if (!data) return <div className="glass-panel p-10 h-[400px] flex items-center justify-center animate-pulse text-gray-500">Loading Matrix...</div>;

  const [[tn, fp], [fn, tp]] = data.matrix;
  const total = tn + fp + fn + tp;

  return (
    <div className="glass-panel p-8">
      <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
        <div className="w-1 h-6 bg-primary rounded-full"></div>
        Classification Confusion Matrix
      </h2>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
        <div className="relative">
          <div className="grid grid-cols-3 gap-1">
            {/* Labels */}
            <div></div>
            <div className="text-center text-[10px] text-gray-500 font-bold uppercase tracking-widest pb-4">Predicted Normal</div>
            <div className="text-center text-[10px] text-gray-500 font-bold uppercase tracking-widest pb-4">Predicted Attack</div>

            <div className="flex items-center justify-end text-[10px] text-gray-500 font-bold uppercase tracking-widest pr-4 rotate-180 [writing-mode:vertical-lr]">Actual Normal</div>
            <div className="aspect-square glass-card bg-success/20 flex flex-col items-center justify-center border-success/30">
              <span className="text-2xl font-bold text-white leading-none">{tn.toLocaleString()}</span>
              <span className="text-[10px] text-success font-bold mt-2">True Negative</span>
            </div>
            <div className="aspect-square glass-card bg-danger/10 flex flex-col items-center justify-center border-danger/20">
              <span className="text-2xl font-bold text-white leading-none">{fp.toLocaleString()}</span>
              <span className="text-[10px] text-danger font-bold mt-2">False Positive</span>
            </div>

            <div className="flex items-center justify-end text-[10px] text-gray-500 font-bold uppercase tracking-widest pr-4 rotate-180 [writing-mode:vertical-lr]">Actual Attack</div>
            <div className="aspect-square glass-card bg-warning/10 flex flex-col items-center justify-center border-warning/20">
              <span className="text-2xl font-bold text-white leading-none">{fn.toLocaleString()}</span>
              <span className="text-[10px] text-warning font-bold mt-2">False Negative</span>
            </div>
            <div className="aspect-square glass-card bg-primary/20 flex flex-col items-center justify-center border-primary/30">
              <span className="text-2xl font-bold text-white leading-none">{tp.toLocaleString()}</span>
              <span className="text-[10px] text-primary font-bold mt-2">True Positive</span>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-white/5 rounded-xl p-6 border border-white/5">
            <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
              <Info size={16} className="text-primary" />
              Insights & Explanations
            </h3>
            <ul className="space-y-4 text-sm text-gray-400">
              <li className="flex gap-3">
                <span className="text-success font-bold text-lg leading-none">•</span>
                <span>The <strong className="text-white">True Negatives ({tn.toLocaleString()})</strong> show traffic that was correctly identified as normal. This indicates high system availability.</span>
              </li>
              <li className="flex gap-3">
                <span className="text-primary font-bold text-lg leading-none">•</span>
                <span>The <strong className="text-white">True Positives ({tp.toLocaleString()})</strong> show threats blocked by the AI engine. This confirms the efficacy of the Isolation Forest.</span>
              </li>
              <li className="flex gap-3">
                <span className="text-danger font-bold text-lg leading-none">•</span>
                <span>Lower <strong className="text-white">False Positives ({fp.toLocaleString()})</strong> are critical to avoid blocking legitimate users.</span>
              </li>
            </ul>
          </div>
          <div className="flex justify-between p-4 bg-primary/5 rounded-lg border border-primary/20">
            <div>
              <div className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">Model Precision</div>
              <div className="text-xl font-bold text-white">{(tp / (tp + fp) * 100).toFixed(1)}%</div>
            </div>
            <div>
              <div className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">Model Recall</div>
              <div className="text-xl font-bold text-white">{(tp / (tp + fn) * 100).toFixed(1)}%</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConfusionMatrix;
