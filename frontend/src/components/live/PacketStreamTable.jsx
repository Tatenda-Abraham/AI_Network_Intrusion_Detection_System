import React, { useState, useRef } from 'react';
import { maskMAC } from '../../api/client';
import { Play, Pause, Filter, ShieldAlert } from 'lucide-react';
import Button from '../ui/Button';

export default function PacketStreamTable({ packets }) {
  const [isPaused, setIsPaused] = useState(false);
  const [filterFlagged, setFilterFlagged] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const frozenPackets = useRef([]);

  const togglePause = () => {
    if (!isPaused) {
      frozenPackets.current = packets;
      setIsPaused(true);
    } else {
      frozenPackets.current = [];
      setIsPaused(false);
    }
  };

  let displayedPackets = isPaused ? frozenPackets.current : packets;
  if (filterFlagged) {
    displayedPackets = displayedPackets.filter(p => p.flagged);
  }
  if (searchTerm.trim()) {
    const term = searchTerm.toLowerCase();
    displayedPackets = displayedPackets.filter(p =>
      (p.transmitter_mac && p.transmitter_mac.toLowerCase().includes(term)) ||
      (p.receiver_mac && p.receiver_mac.toLowerCase().includes(term)) ||
      (p.bssid && p.bssid.toLowerCase().includes(term)) ||
      (p.frame_subtype && String(p.frame_subtype).toLowerCase().includes(term))
    );
  }

  return (
    <div
      className="card panel-tall"
      style={{
        display: 'flex',
        flexDirection: 'column',
        background: '#FFFFFF',
        borderRadius: '10px',
        border: '1px solid var(--cut-border, #CBD5E1)',
        boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
        overflow: 'hidden'
      }}
    >
      <div
        className="card-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 16px',
          borderBottom: '1px solid #E2E8F0',
          background: '#F8FAFC',
          flexWrap: 'wrap',
          gap: '10px'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <h3 style={{ margin: 0, fontSize: '14.5px', fontWeight: '700', color: '#0F172A' }}>
            Live Packet Stream
          </h3>
          <span style={{ fontSize: '11px', background: '#E0F2FE', color: '#0288D1', padding: '2px 8px', borderRadius: '12px', fontWeight: '700' }}>
            Latest {displayedPackets.length} rows
          </span>
          {isPaused && (
            <span style={{ fontSize: '11px', background: '#FEF3C7', color: '#B45309', padding: '2px 8px', borderRadius: '12px', fontWeight: '700' }}>
              PAUSED
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <input
            type="text"
            placeholder="Filter MAC / Type..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              height: '30px',
              padding: '0 8px',
              fontSize: '12px',
              borderRadius: '6px',
              border: '1px solid #CBD5E1',
              outline: 'none',
              width: '130px'
            }}
          />

          <Button
            variant={filterFlagged ? 'primary' : 'secondary'}
            size="sm"
            onClick={() => setFilterFlagged(!filterFlagged)}
            style={{ height: '30px', fontSize: '11.5px', padding: '0 10px' }}
          >
            <ShieldAlert size={13} />
            <span>{filterFlagged ? 'Flagged Only' : 'All Frames'}</span>
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={togglePause}
            style={{ height: '30px', fontSize: '11.5px', padding: '0 10px' }}
          >
            {isPaused ? <Play size={13} color="#16A34A" /> : <Pause size={13} color="#DC2626" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </Button>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table className="cut-table" style={{ fontSize: '12px', width: '100%', borderCollapse: 'collapse' }}>
          <thead style={{ position: 'sticky', top: 0, background: '#F8FAFC', zIndex: 1 }}>
            <tr style={{ borderBottom: '1px solid #E2E8F0', color: '#475569', fontSize: '11px', textTransform: 'uppercase' }}>
              <th style={{ padding: '8px 12px' }}>Delta Time</th>
              <th style={{ padding: '8px 12px' }}>Transmitter MAC</th>
              <th style={{ padding: '8px 12px' }}>Receiver MAC</th>
              <th style={{ padding: '8px 12px' }}>BSSID</th>
              <th style={{ padding: '8px 12px' }}>Frame Type/Subtype</th>
              <th style={{ padding: '8px 12px' }}>RSSI (dBm)</th>
              <th style={{ padding: '8px 12px' }}>Channel</th>
              <th style={{ padding: '8px 12px' }}>Length</th>
            </tr>
          </thead>
          <tbody>
            {displayedPackets.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '48px 12px', color: '#94A3B8' }}>
                  No frames match the active filter or capture is starting...
                </td>
              </tr>
            ) : (
              displayedPackets.map((pkt, i) => (
                <tr
                  key={pkt.id || i}
                  style={{
                    background: pkt.flagged ? '#FFF9E6' : (i % 2 === 0 ? '#FFFFFF' : '#FAFAFA'),
                    borderLeft: pkt.flagged ? '4px solid var(--cut-gold-accent, #D4AF37)' : '4px solid transparent',
                    borderBottom: '1px solid #F1F5F9',
                    fontFamily: 'inherit'
                  }}
                >
                  <td style={{ padding: '6px 12px', color: '#64748B' }}>
                    {typeof pkt.delta_time === 'number' ? pkt.delta_time.toFixed(4) : (pkt.delta_time || '0.0000')}s
                  </td>
                  <td style={{ padding: '6px 12px', fontFamily: 'monospace', fontWeight: pkt.flagged ? '700' : '500', color: pkt.flagged ? '#B78103' : '#1E293B' }}>
                    {maskMAC(pkt.transmitter_mac)}
                  </td>
                  <td style={{ padding: '6px 12px', fontFamily: 'monospace', color: '#475569' }}>
                    {maskMAC(pkt.receiver_mac)}
                  </td>
                  <td style={{ padding: '6px 12px', fontFamily: 'monospace', color: '#64748B' }}>
                    {maskMAC(pkt.bssid)}
                  </td>
                  <td style={{ padding: '6px 12px' }}>
                    <span style={{ background: '#F1F5F9', padding: '1px 6px', borderRadius: '4px', fontSize: '11px', color: '#334155' }}>
                      {pkt.frame_type ?? 'Mgt'}:{pkt.frame_subtype ?? '0'}
                    </span>
                  </td>
                  <td style={{ padding: '6px 12px', fontWeight: '700', color: (pkt.rssi_dbm || pkt.rssi) < -75 ? '#DC2626' : '#16A34A' }}>
                    {pkt.rssi_dbm ?? pkt.rssi ?? -65}
                  </td>
                  <td style={{ padding: '6px 12px', color: '#334155' }}>
                    {pkt.channel ?? 6}
                  </td>
                  <td style={{ padding: '6px 12px', color: '#64748B' }}>
                    {pkt.frame_length ?? pkt.length ?? 0} B
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
