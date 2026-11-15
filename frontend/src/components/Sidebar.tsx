import React from 'react';
import {
  LayoutDashboard,
  Activity,
  FileSpreadsheet,
  ShieldAlert,
  Cpu,
  FileText,
} from 'lucide-react';

export type PageId = 'overview' | 'live' | 'pcap' | 'alerts' | 'models' | 'reports';

interface SidebarProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
  activeAlertsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onSelectPage,
  activeAlertsCount,
}) => {
  const navItems: Array<{ id: PageId; label: string; icon: React.ElementType; badge?: number }> = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'live', label: 'Live Monitoring', icon: Activity },
    { id: 'pcap', label: 'PCAP Analysis', icon: FileSpreadsheet },
    { id: 'alerts', label: 'Alerts', icon: ShieldAlert, badge: activeAlertsCount },
    { id: 'models', label: 'Model Performance', icon: Cpu },
    { id: 'reports', label: 'Security Reports', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-navy-900 border-r border-navy-700/80 flex flex-col justify-between p-4 select-none shrink-0">
      <div>
        <div className="text-[11px] font-semibold text-slate-400 tracking-wider uppercase px-3 mb-3">
          SOC Operations
        </div>
        <nav className="space-y-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectPage(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/80 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className="px-2 py-0.5 text-xs font-mono font-bold rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* System Integrity & Safety Notice */}
      <div className="p-3.5 rounded-xl bg-navy-850 border border-navy-700 text-xs text-slate-400">
        <div className="flex items-center space-x-2 text-slate-300 font-medium mb-1">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span>Passive Sniffer Guard</span>
        </div>
        <p className="text-[11px] leading-relaxed text-slate-400">
          Strictly read-only network tap. Zero packet injection, port scanning, or connection disruption.
        </p>
      </div>
    </aside>
  );
};
