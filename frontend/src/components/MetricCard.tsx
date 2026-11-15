import React from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ElementType;
  accentColor?: 'blue' | 'green' | 'amber' | 'rose' | 'purple';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  accentColor = 'blue',
}) => {
  const colorMap = {
    blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    green: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    amber: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    rose: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
    purple: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  };

  return (
    <div className="p-5 rounded-xl bg-navy-850 border border-navy-700/80 shadow-sm flex items-start justify-between">
      <div>
        <p className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">{title}</p>
        <h3 className="text-2xl font-bold font-mono text-slate-100">{value}</h3>
        {subtitle && <p className="text-xs text-slate-400 mt-1 font-mono">{subtitle}</p>}
      </div>
      <div className={`p-2.5 rounded-lg border ${colorMap[accentColor]}`}>
        <Icon className="w-5 h-5" />
      </div>
    </div>
  );
};
