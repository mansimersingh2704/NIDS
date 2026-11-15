import { useEffect, useRef, useState } from 'react';
import { AlertItem, FlowRecord } from '../types/nids';

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false);
  const [liveFlows, setLiveFlows] = useState<FlowRecord[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<AlertItem[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let timeoutId: number;

    const connect = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/api/ws`;

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'flow') {
            setLiveFlows((prev) => [msg.data, ...prev.slice(0, 49)]);
          } else if (msg.type === 'alert') {
            setLiveAlerts((prev) => [msg.data, ...prev.slice(0, 49)]);
          } else if (msg.type === 'init') {
            if (msg.data.recent_detections) {
              setLiveFlows(msg.data.recent_detections);
            }
          }
        } catch (e) {
          // ignore non-json pongs
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        timeoutId = window.setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      clearTimeout(timeoutId);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  return { isConnected, liveFlows, liveAlerts };
}
