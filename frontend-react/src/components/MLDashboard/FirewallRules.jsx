import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ShieldAlert, RefreshCw, AlertOctagon, Info } from 'lucide-react';
import { clsx } from 'clsx';

const API_ROOT = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const FirewallRules = () => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchRules = async () => {
    setLoading(true);
    setError(null);
    try {
        // Use a relative path if proxy is configured, or API_ROOT
        const url = API_ROOT.includes('localhost')
            ? 'http://localhost:5000/api/firewall-rules'
            : '/api/firewall-rules';

      const res = await axios.get(url, { timeout: 5000 });
      setRules(res.data);
    } catch (err) {
      const serverError = err.response?.data?.error;
      setError(serverError || err.message || 'Failed to connect to backend engine');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
    // Auto refresh every 10 seconds
    const interval = setInterval(fetchRules, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="w-full">
      <div className="flex justify-between items-center mb-6 px-1">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <ShieldAlert className="w-6 h-6 text-primary glow-icon" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white tracking-tight">Active Firewall Rules</h3>
            <p className="text-xs text-gray-400 font-medium">Live iptables INPUT chain configuration</p>
          </div>
        </div>

        <button
          onClick={fetchRules}
          disabled={loading}
          className={clsx(
            "flex items-center px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-sm font-medium transition-all duration-300",
            loading ? "opacity-50 cursor-not-allowed" : "hover:bg-white/10 hover:border-white/20 hover:shadow-[0_0_15px_rgba(255,255,255,0.05)] cursor-pointer"
          )}
        >
          <RefreshCw className={clsx("w-4 h-4 mr-2", loading && "animate-spin")} />
          Reload Rules
        </button>
      </div>

      {error ? (
        <div className="bg-danger/10 border border-danger/30 rounded-xl p-6 text-center shadow-[inset_0_0_20px_rgba(239,68,68,0.1)]">
          <AlertOctagon className="w-10 h-10 text-danger mx-auto mb-3 animate-pulse" />
          <h4 className="text-danger font-bold mb-1">Retrieval Failed</h4>
          <p className="text-sm text-gray-300 mb-4">{error}</p>
          <button
            onClick={fetchRules}
            className="px-6 py-2 bg-danger/20 hover:bg-danger/30 text-danger rounded-lg text-sm font-bold transition-colors"
          >
            Retry Connection
          </button>
        </div>
      ) : (
        <div className="w-full overflow-hidden rounded-xl border border-white/5 backdrop-blur-xl bg-darker/60 shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-gray-400 uppercase bg-white/5 border-b border-white/5 font-semibold">
                <tr>
                  <th className="px-6 py-4 rounded-tl-xl">Chain</th>
                  <th className="px-6 py-4">Num</th>
                  <th className="px-6 py-4">Action</th>
                  <th className="px-6 py-4">Protocol</th>
                  <th className="px-6 py-4">Source</th>
                  <th className="px-6 py-4">Destination</th>
                  <th className="px-6 py-4">Packets / Bytes</th>
                  <th className="px-6 py-4 rounded-tr-xl">Additional Info</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {loading && rules.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="px-6 py-12 text-center text-gray-400">
                      <div className="flex flex-col items-center justify-center">
                        <RefreshCw className="w-6 h-6 animate-spin text-primary mb-3" />
                        <span className="font-medium tracking-wider">LOADING FIREWALL DATABASE...</span>
                      </div>
                    </td>
                  </tr>
                ) : rules.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="px-6 py-12 text-center text-gray-400">
                      <Info className="w-6 h-6 text-gray-500 mx-auto mb-2" />
                      No active rules found in any chain.
                    </td>
                  </tr>
                ) : (
                  rules.map((rule, idx) => (
                    <tr
                      key={idx}
                      className="hover:bg-white/[0.02] transition-colors duration-200 group"
                    >
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-gray-300 font-mono text-xs font-bold uppercase">
                          {rule.chain}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="px-2 py-1 bg-white/5 rounded-md text-xs font-mono text-gray-300 border border-white/5">
                          {rule.num}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={clsx(
                          "px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider",
                          rule.target === 'DROP' ? 'bg-danger/20 text-danger border border-danger/20' :
                          rule.target === 'ACCEPT' ? 'bg-success/20 text-success border border-success/20' :
                          'bg-primary/20 text-primary border border-primary/20'
                        )}>
                          {rule.target}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-gray-300 font-mono text-xs font-medium uppercase">
                          {rule.prot === 'all' ? 'ANY' : rule.prot}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={clsx(
                          "font-mono text-xs",
                          rule.source === '0.0.0.0/0' ? "text-gray-500" : "text-white glow-text-sm"
                        )}>
                          {rule.source}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={clsx(
                          "font-mono text-xs",
                          rule.destination === '0.0.0.0/0' ? "text-gray-500" : "text-gray-300"
                        )}>
                          {rule.destination}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex flex-col">
                          <span className="text-xs text-gray-300">{rule.pkts} pkts</span>
                          <span className="text-[10px] text-gray-500">{rule.bytes}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-xs text-gray-400 font-medium font-mono truncate max-w-[200px]">
                        {rule.extras || <span className="opacity-50">—</span>}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default FirewallRules;
