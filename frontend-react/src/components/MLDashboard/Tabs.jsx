import React from 'react';

const Tabs = ({ activeTab, setActiveTab }) => {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'confusion', label: 'Confusion Matrix' },
    { id: 'roc', label: 'ROC Curve' },
    { id: 'importance', label: 'Feature Importance' },
    { id: 'anomaly', label: 'Anomaly Scores' },
    { id: 'logs', label: 'Live Predictions' },
  ];

  return (
    <div className="flex bg-white/5 p-1 rounded-2xl border border-white/10 w-fit backdrop-blur-md">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => setActiveTab(tab.id)}
          className={`px-6 py-2.5 rounded-xl text-xs font-bold transition-all duration-300 ${
            activeTab === tab.id
              ? 'bg-blue-600 text-white shadow-lg'
              : 'text-gray-400 hover:text-white hover:bg-white/5'
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
};

export default Tabs;
