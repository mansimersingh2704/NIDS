import React, { useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, PageId } from './components/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { LiveMonitoringPage } from './pages/LiveMonitoringPage';
import { PcapAnalysisPage } from './pages/PcapAnalysisPage';
import { AlertsPage } from './pages/AlertsPage';
import { ModelPerformancePage } from './pages/ModelPerformancePage';
import { ReportsPage } from './pages/ReportsPage';
import { useWebSocket } from './hooks/useWebSocket';
import { api } from './services/api';
import { CaptureStatus, DashboardOverview } from './types/nids';

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<PageId>('overview');
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);
  const [activeModel, setActiveModel] = useState<string>('random_forest');

  const { isConnected, liveFlows, liveAlerts } = useWebSocket();

  const fetchDashboardData = () => {
    api.getDashboardOverview()
      .then((res) => setOverview(res.data))
      .catch((err) => console.error('Error fetching overview:', err));

    api.getCaptureStatus()
      .then((res) => setCaptureStatus(res.data))
      .catch((err) => console.error('Error fetching capture status:', err));

    api.getModelInfo()
      .then((res) => setActiveModel(res.data.active_model))
      .catch((err) => console.error('Error fetching model info:', err));
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="h-screen w-screen flex flex-col bg-navy-950 text-slate-100 overflow-hidden font-sans">
      {/* Top Navbar */}
      <Navbar
        isCaptureRunning={captureStatus?.is_running ?? false}
        activeInterface={captureStatus?.interface ?? null}
        activeModel={activeModel}
        wsConnected={isConnected}
      />

      {/* Main Layout Area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          currentPage={currentPage}
          onSelectPage={setCurrentPage}
          activeAlertsCount={overview?.active_alerts ?? 0}
        />

        {/* Content Pane */}
        <main className="flex-1 overflow-y-auto p-6 bg-navy-900/60">
          <div className="max-w-7xl mx-auto pb-12">
            {currentPage === 'overview' && (
              <OverviewPage
                overview={overview}
                onNavigateToAlerts={() => setCurrentPage('alerts')}
                onNavigateToLive={() => setCurrentPage('live')}
              />
            )}
            {currentPage === 'live' && (
              <LiveMonitoringPage
                liveFlows={liveFlows}
                liveAlerts={liveAlerts}
                captureStatus={captureStatus}
                onRefreshStatus={fetchDashboardData}
              />
            )}
            {currentPage === 'pcap' && <PcapAnalysisPage />}
            {currentPage === 'alerts' && <AlertsPage />}
            {currentPage === 'models' && <ModelPerformancePage />}
            {currentPage === 'reports' && <ReportsPage />}
          </div>
        </main>
      </div>
    </div>
  );
};

export default App;
