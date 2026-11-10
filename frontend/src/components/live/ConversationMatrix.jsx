import React from 'react';
import { maskMAC } from '../../api/client';

export default function ConversationMatrix({ conversations }) {
  return (
    <div className="card panel-tall" style={{ display: 'flex', flexDirection: 'column' }}>
      <div className="card-header">
        <h3>Device Conversations</h3>
        <span className="count-pill">{conversations.length} pairs</span>
      </div>
      <div style={{ flex: 1, overflowX: 'auto' }}>
        <table className="cut-table">
          <thead>
            <tr>
              <th>Device Pair (Source → Dest)</th>
              <th>Packets</th>
              <th>Volume</th>
              <th>Packets / sec</th>
              <th>Vendor</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {conversations.length === 0 ? (
              <tr>
                <td colSpan="6" className="table-note">
                  Conversations appear as soon as the first window of frames is rebuilt.
                </td>
              </tr>
            ) : conversations.map((conv) => (
              <tr key={conv.id}>
                <td className="mono">
                  <span style={{ color: 'var(--cut-blue-primary)', fontWeight: 700 }}>{maskMAC(conv.mac_a)}</span>
                  <span className="arrow">→</span>
                  {maskMAC(conv.mac_b)}
                </td>
                <td>{(conv.packets || 0).toLocaleString()}</td>
                <td>{((conv.bytes || 0) / 1024).toFixed(2)} KB</td>
                <td style={{ color: 'var(--cut-blue-primary)', fontWeight: 800 }}>
                  {(conv.packets_per_second ?? 0).toFixed(1)}
                </td>
                <td style={{ fontSize: '11px', color: 'var(--cut-text-muted)' }}>
                  {conv.vendor_a || 'Unknown'}{conv.vendor_b && conv.vendor_b !== conv.vendor_a ? ` / ${conv.vendor_b}` : ''}
                </td>
                <td>{conv.last_seen ? new Date(conv.last_seen).toLocaleTimeString() : '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
