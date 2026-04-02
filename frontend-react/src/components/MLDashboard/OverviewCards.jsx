import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Target, Shield, Cpu, Activity, Zap, Info, CheckCircle, Database } from 'lucide-react';
import { clsx } from 'clsx';

const OverviewCards = () => {
    const [metrics, setMetrics] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchMetrics = async () => {
            try {
                const response = await axios.get('/api/ml-metrics');
                setMetrics(response.data);
            } catch (error) {
                console.error("Error fetching ML metrics:", error);
            } finally {
                setLoading(false);
            }
        };
        fetchMetrics();
    }, []);

    const metricItems = [
        { label: 'Accuracy', key: 'accuracy', icon: Target, color: 'text-blue-400', desc: 'Overall classification correctness across all traffic samples.' },
        { label: 'Precision', key: 'precision', icon: Shield, color: 'text-emerald-400', desc: 'Ratio of true threats to all samples classified as attack.' },
        { label: 'Recall', key: 'recall', icon: Activity, color: 'text-purple-400', desc: 'Ability to detect all actual attacks without missing threats.' },
        { label: 'F1 Score', key: 'f1_score', icon: Zap, color: 'text-orange-400', desc: 'Harmonic mean of precision and recall for balanced evaluation.' },
        { label: 'ROC-AUC', key: 'roc_auc', icon: Info, color: 'text-pink-400', desc: 'Model probability separation threshold performance.' },
    ];

    if (loading) return <div className="text-center py-20 text-gray-500 animate-pulse">Loading intelligence overview...</div>;

    return (
        <div className="space-y-12 animate-in fade-in duration-1000">
            {/* KPI Section */}
            <div>
                <h3 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                    <Activity className="text-primary w-5 h-5" /> 
                    Model Performance KPIs
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                    {metricItems.map((item) => (
                        <div key={item.label} className="glass-card p-5 group flex flex-col justify-between h-full">
                            <div>
                                <div className="flex justify-between items-start mb-4">
                                    <div className={`p-2 rounded-lg bg-white/5 ${item.color} group-hover:bg-white/10 transition-colors`}>
                                        <item.icon className="w-5 h-5" />
                                    </div>
                                    <span className={`text-2xl font-bold tracking-tight ${item.color}`}>
                                        {metrics ? (typeof metrics[item.key] === 'number' ? `${(metrics[item.key] * 100).toFixed(1)}%` : metrics[item.key]) : '--'}
                                    </span>
                                </div>
                                <h4 className="text-gray-300 font-bold text-sm mb-1">{item.label}</h4>
                                <p className="text-[11px] text-gray-500 leading-relaxed font-medium">{item.desc}</p>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Intelligence Context Ported from Analysis Page */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Detection Logic */}
                <div className="glass-panel p-8 space-y-4 lg:col-span-2">
                    <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                        <Cpu className="text-primary w-5 h-5" />
                        How ML Firewall Works
                    </h3>
                    <div className="space-y-6">
                        <section>
                            <h4 className="text-primary text-xs font-bold uppercase tracking-widest mb-2">Algorithm Essence</h4>
                            <p className="text-gray-300 leading-relaxed text-sm">
                                Our firewall utilizes the <span className="text-white font-semibold">Isolation Forest</span> algorithm. Unlike traditional models that learn what "normal" looks like, Isolation Forest works by specifically isolating anomalies. It assumes that threats are few and different, making them easier to "branch off" in a decision tree structure.
                            </p>
                        </section>
                        <section>
                            <h4 className="text-emerald-400 text-xs font-bold uppercase tracking-widest mb-2">Real-Time Inference</h4>
                            <p className="text-gray-300 leading-relaxed text-sm">
                                Every packet flow is converted into a feature vector (duration, packet count, byte rates, etc.). The model assigns an <span className="text-white font-semibold">Anomaly Score</span>. If the score exceeds our high-precision threshold, the firewall triggers an immediate IPTables block to neutralize the threat.
                            </p>
                        </section>
                    </div>
                </div>

                {/* Training Context */}
                <div className="glass-panel p-8 space-y-6">
                    <div className="flex items-center gap-3 mb-4">
                        <Database className="text-purple-400 w-6 h-6" />
                        <h3 className="text-xl font-bold text-white">Model Context</h3>
                    </div>
                    
                    <div className="space-y-6">
                        <div className="p-4 bg-white/5 rounded-xl border border-white/5">
                            <h4 className="text-gray-400 text-[10px] font-bold uppercase tracking-widest mb-1">Active Model</h4>
                            <p className="text-white font-medium">Isolation Forest (v2.1)</p>
                        </div>
                        <div className="p-4 bg-white/5 rounded-xl border border-white/5">
                            <h4 className="text-gray-400 text-[10px] font-bold uppercase tracking-widest mb-1">Knowledge Source</h4>
                            <p className="text-white font-medium">UNSW-NB15 Benchmark</p>
                        </div>
                        
                        <ul className="space-y-3 pt-2">
                            <li className="flex items-start gap-3 text-xs text-gray-400">
                                <CheckCircle className="text-emerald-500 w-4 h-4 mt-0.5 flex-shrink-0" />
                                Unsupervised anomaly isolation
                            </li>
                            <li className="flex items-start gap-3 text-xs text-gray-400">
                                <CheckCircle className="text-emerald-500 w-4 h-4 mt-0.5 flex-shrink-0" />
                                Scalable to high-throughput networks
                            </li>
                            <li className="flex items-start gap-3 text-xs text-gray-400">
                                <CheckCircle className="text-emerald-500 w-4 h-4 mt-0.5 flex-shrink-0" />
                                Robust against zero-day exploits
                            </li>
                        </ul>
                    </div>
                </div>
            </div>

            {/* Project Objectives */}
            <div className="glass-panel p-8 bg-gradient-to-br from-white/5 to-transparent border-t-primary/20">
                <h3 className="text-lg font-bold text-white mb-6">Strategic Defense Objectives</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                    <div className="space-y-2">
                        <div className="flex items-center gap-2 text-primary font-bold text-sm">
                            <span className="w-2 h-2 rounded-full bg-primary glow-sm"></span>
                            Zero-Day Detection
                        </div>
                        <p className="text-gray-500 text-xs leading-relaxed">Identifying never-before-seen attack patterns without traditional static signatures.</p>
                    </div>
                    <div className="space-y-2">
                        <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                            <span className="w-2 h-2 rounded-full bg-emerald-400 glow-sm"></span>
                            Minimal Latency
                        </div>
                        <p className="text-gray-500 text-xs leading-relaxed">Optimized preprocessing ensuring per-packet analysis doesn't slow down network throughput.</p>
                    </div>
                    <div className="space-y-2">
                        <div className="flex items-center gap-2 text-purple-400 font-bold text-sm">
                            <span className="w-2 h-2 rounded-full bg-purple-400 glow-sm"></span>
                            Active Defense
                        </div>
                        <p className="text-gray-500 text-xs leading-relaxed">Seamless integration with Linux kernel firewalling (Netfilter/IPTables) for instant response.</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default OverviewCards;
