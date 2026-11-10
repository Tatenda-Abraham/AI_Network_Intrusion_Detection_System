import React, { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../api/client';
import { useToast } from '../contexts/ToastContext';
import WirelessStatusBar from '../components/live/WirelessStatusBar';
import LiveDetectionsTable from '../components/live/LiveDetectionsTable';
import PacketStreamTable from '../components/live/PacketStreamTable';
import ConversationMatrix from '../components/live/ConversationMatrix';
import LiveFindingsLog from '../components/live/LiveFindingsLog';
import AlertTimeline from '../components/live/AlertTimeline';

const DEFAULT_REFRESH_SECONDS = 5;

export default function LiveMonitorPage() {
  const [status, setStatus] = useState(null);
  const [detections, setDetections] = useState([]);
  const [packets, setPackets] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [findings, setFindings] = useState([]);
  const [timeline, setTimeline] = useState({ labels: [], counts: [] });
  const [windows, setWindows] = useState([]);
  const [adapters, setAdapters] = useState([]);
  const [selectedAdapter, setSelectedAdapter] = useState('');
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [busy, setBusy] = useState(false);
  const [countdown, setCountdown] = useState(DEFAULT_REFRESH_SECONDS);

  const { success, error } = useToast();
  const startedRef = useRef(false);
  const countdownRef = useRef(DEFAULT_REFRESH_SECONDS);

  const refreshAll = useCallback(async () => {
    const [st, det, pkt, conv, find, time, win] = await Promise.allSettled([
      api.live.getStatus(),
      api.live.getDetections({ limit: 25, flagged_only: flaggedOnly }),
      api.live.getPackets({ limit: 100 }),
      api.live.getConversations({ limit: 25 }),
      api.live.getFindings({ limit: 25 }),
      api.live.getTimeline(),
      api.live.getWindows()
    ]);

    const value = (settled, fallback) => (settled.status === 'fulfilled' ? settled.value : fallback);

    const stVal = value(st, null);
    if (stVal) {
      setStatus(stVal);
      countdownRef.current = stVal.refresh_interval_seconds || DEFAULT_REFRESH_SECONDS;
      setCountdown(countdownRef.current);
    }
    setDetections(value(det, { detections: [] }).detections || []);
    setPackets(value(pkt, { packets: [] }).packets || []);
    setConversations(value(conv, { conversations: [] }).conversations || []);
    setFindings(value(find, { findings: [] }).findings || []);
    setTimeline(value(time, { labels: [], counts: [] }));
    setWindows(value(win, { windows: [] }).windows || []);
  }, [flaggedOnly]);

  const startMonitoring = useCallback(async (interfaceId) => {
    setBusy(true);
    try {
      const res = await api.capture.start(interfaceId ? { interface_id: interfaceId } : {});
      success(res.message || 'Live monitoring started');
      await refreshAll();
    } catch (err) {
      error(`Monitoring could not start: ${err.message}`);
    } finally {
      setBusy(false);
    }
  }, [refreshAll, success, error]);

  const stopMonitoring = async () => {
    setBusy(true);
    try {
      const res = await api.capture.stop();
      success(res.message || 'Live monitoring paused');
      await refreshAll();
    } catch (err) {
      error(`Monitoring could not stop: ${err.message}`);
    } finally {
      setBusy(false);
    }
  };

  // Opening the monitor brings the capture engine up on the active adapter by itself.
  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;

    (async () => {
      try {
        const st = await api.live.getStatus();
        setStatus(st);
        countdownRef.current = st.refresh_interval_seconds || DEFAULT_REFRESH_SECONDS;
        setCountdown(countdownRef.current);
        if (!st.is_capturing && st.capture_state !== 'RESTARTING') {
          await startMonitoring();
        }
      } catch (err) {
        error(`Monitor status unavailable: ${err.message}`);
      }
      try {
        const list = await api.capture.getInterfaces();
        const usable = (list.interfaces || []).filter((i) => !i.is_virtual);
        setAdapters(usable);
      } catch (err) {
        console.error('Adapter list unavailable:', err);
      }
    })();
  }, [startMonitoring, error]);

  useEffect(() => {
    refreshAll();
    let nextRefreshIn = countdownRef.current;

    const tick = setInterval(async () => {
      nextRefreshIn -= 1;
      if (nextRefreshIn <= 0) {
        nextRefreshIn = countdownRef.current;
        await refreshAll();
      }
      setCountdown(nextRefreshIn);
    }, 1000);

    return () => clearInterval(tick);
  }, [refreshAll]);

  const activeAdapter = status?.device;

  return (
    <div className="live-monitor-page">
      <div className="page-head">
        <div>
          <h2>Live Monitor &mdash; Wireshark / TShark Capture</h2>
          <p>
            Frames are dissected in rolling windows, rebuilt into flows, classified by the same
            Random Forest model used on the campus test data and written to the events database.
          </p>
        </div>
      </div>

      <WirelessStatusBar
        status={status}
        countdown={countdown}
        busy={busy}
        onRefresh={refreshAll}
        onStart={() => startMonitoring()}
        onStop={stopMonitoring}
      />

      {status?.last_error && (
        <div className="inline-note warning">{status.last_error}</div>
      )}

      <div className="card adapter-card">
        <div className="adapter-row">
          <div>
            <h3>Monitoring Source</h3>
            <p>
              Currently reading <b>{status?.adapter || 'the auto-selected adapter'}</b>
              {status?.selection_method ? ` (${status.selection_method})` : ''}.
              Pick another adapter to move the monitor onto a mirrored SPAN port or a second NIC.
            </p>
          </div>
          <div className="adapter-controls">
            <select
              className="form-select"
              value={selectedAdapter}
              onChange={(e) => setSelectedAdapter(e.target.value)}
            >
              <option value="">Auto-select active adapter</option>
              {adapters.map((a) => (
                <option key={a.device} value={a.device}>
                  {a.index}. {a.friendly_name}{a.is_active ? ' - active' : ''}{a.device === activeAdapter ? ' - monitoring now' : ''}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="btn-primary"
              disabled={busy}
              onClick={() => startMonitoring(selectedAdapter || undefined)}
            >
              Monitor This Source
            </button>
          </div>
        </div>
      </div>

      <LiveDetectionsTable
        detections={detections}
        flaggedOnly={flaggedOnly}
        onToggleFlagged={() => setFlaggedOnly((v) => !v)}
      />

      <div className="split-2">
        <PacketStreamTable packets={packets} />
        <ConversationMatrix conversations={conversations} />
      </div>

      <div className="split-2">
        <LiveFindingsLog findings={findings} />
        <div className="stack-2">
          <AlertTimeline alertData={timeline} />
          <div className="card">
            <div className="card-header">
              <h3>Capture Windows</h3>
              <span className="count-pill">{windows.length} latest</span>
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table className="cut-table">
                <thead>
                  <tr>
                    <th>Window End</th>
                    <th>Frames</th>
                    <th>Packets / sec</th>
                    <th>Findings</th>
                    <th>Processing</th>
                  </tr>
                </thead>
                <tbody>
                  {windows.length === 0 ? (
                    <tr>
                      <td colSpan="5" className="table-note">
                        The first window closes a few seconds after the capture starts.
                      </td>
                    </tr>
                  ) : windows.slice(0, 8).map((w) => (
                    <tr key={w.id}>
                      <td>{w.start ? new Date(w.start).toLocaleTimeString() : '-'}</td>
                      <td>{(w.frames || 0).toLocaleString()}</td>
                      <td>{(w.pps ?? 0).toFixed(1)}</td>
                      <td>{w.findings || 0}</td>
                      <td>{(w.processing_ms ?? 0).toFixed(0)} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
