import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Target, 
  Activity, 
  BarChart3, 
  ShieldAlert, 
  History, 
  TrendingUp, 
  BrainCircuit,
  Zap,
  LayoutDashboard
} from 'lucide-react';
import OverviewCards from './OverviewCards';
import ConfusionMatrix from './ConfusionMatrix';
import RocCurve from './RocCurve';
import FeatureImportance from './FeatureImportance';
import AnomalyChart from './AnomalyChart';
import PredictionTable from './PredictionTable';
import FirewallRules from './FirewallRules';
import { clsx } from 'clsx';

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState(() => {
    const hash = window.location.hash.replace('#', '');
    return hash || 'overview';
  });

  // Update hash when tab changes
  useEffect(() => {
    window.location.hash = activeTab;
  }, [activeTab]);

  const tabs = [
    { id: 'overview', label: 'Intelligence Overview', icon: BrainCircuit },
    { id: 'confusion', label: 'Confusion Matrix', icon: Target },
    { id: 'roc', label: 'ROC Curve', icon: TrendingUp },
    { id: 'importance', label: 'Feature Importance', icon: BarChart3 },
    { id: 'anomaly', label: 'Anomaly Distribution', icon: Zap },
    { id: 'live', label: 'Live Traffic', icon: Activity },
    { id: 'rules', label: 'Active Rules', icon: ShieldAlert },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewCards />;
      case 'confusion':
        return (
          <div className="glass-panel p-8 min-h-[500px]">
            <h3 className="text-xl font-bold text-white mb-8 flex items-center gap-2">
              <Target className="text-primary w-5 h-5" />
              Model Confidence Matrix (TP/FP/TN/FN)
            </h3>
            <ConfusionMatrix />
          </div>
        );
      case 'roc':
        return (
          <div className="glass-panel p-8 min-h-[500px]">
            <h3 className="text-xl font-bold text-white mb-8 flex items-center gap-2">
              <TrendingUp className="text-primary w-5 h-5" />
              Performance (ROC Curve / AUC)
            </h3>
            <RocCurve />
          </div>
        );
      case 'importance':
        return (
          <div className="glass-panel p-8 min-h-[500px]">
            <h3 className="text-xl font-bold text-white mb-8 flex items-center gap-2">
              <BarChart3 className="text-primary w-5 h-5" />
              Machine Learning Feature Significance
            </h3>
            <FeatureImportance fullWidth />
          </div>
        );
      case 'anomaly':
        return (
          <div className="glass-panel p-8 min-h-[500px]">
            <h3 className="text-xl font-bold text-white mb-8 flex items-center gap-2">
              <Zap className="text-danger w-5 h-5" />
              Anomaly Score Density Distribution
            </h3>
            <AnomalyChart fullWidth />
          </div>
        );
      case 'live':
        return (
          <div className="glass-panel p-8">
            <h3 className="text-xl font-bold text-white mb-8 flex items-center gap-2">
              <History className="text-success w-5 h-5" />
              Real-time Traffic Intelligence Logs
            </h3>
            <PredictionTable />
          </div>
        );
      case 'rules':
        return (
          <div className="glass-panel p-8 min-h-[500px]">
            <FirewallRules />
          </div>
        );
      default:
        return <OverviewCards />;
    }
  };

  return (
    <div className="min-h-screen bg-darker text-gray-100 flex flex-col font-sans">
      {/* Centered Professional Top Navigation */}
      <header className="sticky top-0 z-50 glass-panel border-b border-white/5 px-8 pt-6 pb-4 backdrop-blur-2xl bg-darker/80">
        <div className="max-w-[1400px] mx-auto flex flex-col items-center">
          {/* Logo Area */}
          <div className="flex items-center space-x-4 mb-6">
            <div className="w-2.5 h-2.5 rounded-full bg-primary animate-pulse shadow-[0_0_15px_rgba(59,130,246,0.8)]"></div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-3">
              <span className="text-gradient">Adaptive ML</span>
              <span className="text-gray-500 font-light text-xs border-l border-white/10 pl-3">Firewall</span>
            </h1>
          </div>
          
          {/* Menu Bar */}
          <nav className="flex items-center space-x-1 p-1 bg-white/5 rounded-2xl border border-white/10 backdrop-blur-lg mb-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  "flex items-center px-4 py-2.5 rounded-xl text-xs font-bold transition-all duration-300",
                  activeTab === tab.id
                    ? "bg-primary text-white shadow-[0_0_15px_rgba(59,130,246,0.3)] transform scale-105"
                    : "text-gray-400 hover:text-white hover:bg-white/5"
                )}
              >
                <tab.icon className={clsx("w-3.5 h-3.5 mr-2", activeTab === tab.id ? "text-white" : "text-gray-500")} />
                {tab.label}
              </button>
            ))}
            <div className="w-px h-5 bg-white/10 mx-2"></div>
            <a 
              href="/" 
              className="flex items-center px-4 py-2.5 rounded-xl text-xs font-bold text-gray-400 hover:text-white hover:bg-white/5 transition-all duration-300"
            >
              Exit
            </a>
          </nav>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-[1400px] mx-auto w-full p-8 mt-2 animate-in fade-in slide-in-from-bottom-6 duration-1000 fill-mode-forwards">
        <div className="mb-8 text-center">
          <h2 className="text-[10px] font-bold text-primary uppercase tracking-[0.4em] mb-2 opacity-80">Security Analytics Dashboard</h2>
          <p className="text-3xl font-light text-white tracking-tight">
            {tabs.find(t => t.id === activeTab)?.label}
          </p>
        </div>
        
        <div className="transition-all duration-500">
          {renderContent()}
        </div>
      </main>

      {/* Modern Footer */}
      <footer className="py-10 text-center border-t border-white/5 bg-darker/50 mt-16">
        <div className="max-w-[1400px] mx-auto px-8">
          <div className="flex justify-center items-center space-x-12 mb-4">
            <div className="flex flex-col items-center">
              <span className="text-[9px] text-gray-500 font-bold uppercase tracking-widest mb-1">Detection Logic</span>
              <span className="text-xs text-gray-300 font-medium tracking-wide">Isolation Forest v2.1</span>
            </div>
            <div className="w-px h-6 bg-white/5"></div>
            <div className="flex flex-col items-center">
              <span className="text-[9px] text-gray-500 font-bold uppercase tracking-widest mb-1">Knowledge Base</span>
              <span className="text-xs text-gray-300 font-medium tracking-wide">UNSW-NB15 Dataset</span>
            </div>
            <div className="w-px h-6 bg-white/5"></div>
            <div className="flex flex-col items-center">
              <span className="text-[9px] text-gray-500 font-bold uppercase tracking-widest mb-1">Status</span>
              <span className="text-xs text-success font-bold tracking-widest uppercase glow-text-sm">Engine Active</span>
            </div>
          </div>
          <p className="text-gray-600 text-[9px] tracking-[0.2em] font-medium uppercase pt-4">
            &copy; 2026 Adaptive ML Firewall | Intelligent Threat Neutralization Suite
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;
