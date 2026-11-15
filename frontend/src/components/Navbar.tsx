import React from 'react';
import { Shield, Eye, Cpu, Radio } from 'lucide-react';

interface NavbarProps {
  isCaptureRunning: boolean;
  activeInterface: string | null;
  activeModel: string;
  wsConnected: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  isCaptureRunning,
  activeInterface,
  activeModel,
  wsConnected,
}) => {
  return (
    <header className="h-16 bg-navy-900 border-b border-navy-700/80 px-6 flex items-center justify-between select-none">
      {/* Brand & System Mode */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/30 text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-slate-100 tracking-wide text-base">AI-NIDS</span>
              <span className="text-[10px] uppercase font-semibold tracking-wider px-1.5 py-0.5 rounded bg-blue-950/80 text-blue-300 border border-blue-800/60">
                SOC v1.0
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">Autonomous Network Intrusion Detection</p>
          </div>
        </div>

        {/* Security Constraint Badge */}
        <div className="hidden lg:flex items-center space-x-1.5 px-3 py-1 rounded-full bg-emerald-950/50 border border-emerald-800/60 text-emerald-400 text-xs">
          <Eye className="w-3.5 h-3.5" />
          <span className="font-medium tracking-tight">PASSIVE MONITORING MODE (READ-ONLY)</span>
        </div>
      </div>

      {/* Live System State Indicators */}
      <div className="flex items-center space-x-4">
        {/* ML Model Pill */}
        <div className="flex items-center space-x-2 px-3 py-1 bg-navy-800 border border-navy-700 rounded-lg text-xs font-mono text-slate-300">
          <Cpu className="w-3.5 h-3.5 text-indigo-400" />
          <span className="text-slate-400">Engine:</span>
          <span className="font-semibold text-indigo-300 uppercase">{activeModel.replace('_', ' ')}</span>
        </div>

        {/* Live Sniffer Status */}
        <div className="flex items-center space-x-2 px-3 py-1 bg-navy-800 border border-navy-700 rounded-lg text-xs font-mono">
          <span className={`w-2 h-2 rounded-full ${isCaptureRunning ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
          <span className="text-slate-400">Capture:</span>
          <span className={isCaptureRunning ? 'text-emerald-400 font-medium' : 'text-slate-400 font-medium'}>
            {isCaptureRunning ? (activeInterface ? `ACTIVE (${activeInterface.slice(0, 14)}...)` : 'ACTIVE') : 'IDLE'}
          </span>
        </div>

        {/* WebSocket Live Telemetry Indicator */}
        <div className="flex items-center space-x-1.5 text-xs font-mono text-slate-400">
          <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400' : 'text-rose-400'}`} />
          <span>{wsConnected ? 'Live Feed' : 'Offline'}</span>
        </div>
      </div>
    </header>
  );
};
