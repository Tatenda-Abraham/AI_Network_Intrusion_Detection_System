import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle, AlertOctagon, HelpCircle, Send } from 'lucide-react';
import { api, getCurrentUser, maskMAC } from '../api/client';
import { useToast } from '../contexts/ToastContext';
import PromptDialog from './PromptDialog';
import { SeverityBadge, Button } from './ui';

export default function ThreatDetailModal({ event, onClose, onUpdated }) {
  const [loading, setLoading] = useState(false);
  const [noteText, setNoteText] = useState('');
  const [actionNotice, setActionNotice] = useState('');
  const [showNotePrompt, setShowNotePrompt] = useState(false);
  const user = getCurrentUser();
  const isAdmin = user?.role === 'Administrator';
  const { success, error } = useToast();

  if (!event) return null;

  const handleStatusChange = async (newStatus) => {
    setLoading(true);
    try {
      await api.events.updateStatus(event.id, newStatus);
      setActionNotice(`Status updated to ${newStatus}`);
      if (onUpdated) onUpdated();
      success(`Status updated to ${newStatus}`);
    } catch (err) {
      error(`Error updating status: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleAddNote = async (note) => {
    setLoading(true);
    try {
      await api.events.addNote(event.id, note);
      setActionNotice('Administrative note recorded');
      if (onUpdated) onUpdated();
      success('Note recorded successfully');
    } catch (err) {
      error(`Error saving note: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Adaptive "Why it was flagged" section based on attack type
  const renderAdaptiveEvidence = () => {
    const stats = event.traffic_stats || {};
    const evJson = event.evidence_json || {};

    switch (event.attack_type) {
      case 'Port Scanning':
        const probedPorts = evJson.probed_ports || evJson.probed_ports_sample || [];
        return (
          <div style={{ background: '#F0F9FF', padding: '14px', borderRadius: '8px', border: '1px solid #BAE6FD' }}>
            <h4 style={{ color: '#0369A1', fontSize: '13px', margin: '0 0 6px 0', fontWeight: '700' }}>
              Probed Port Distribution & Asymmetry
            </h4>
            <p style={{ fontSize: '13px', margin: '0 0 8px 0', color: 'var(--cut-text-main)' }}>
              Detected single source scanning across multiple destination ports with unacknowledged TCP SYN probes.
            </p>
            {probedPorts.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                {probedPorts.map((p, i) => (
                  <span key={i} style={{ background: '#E0F2FE', color: '#0369A1', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace' }}>
                    Port {p}
                  </span>
                ))}
              </div>
            )}
          </div>
        );

      case 'DoS':
      case 'DDoS':
        const sources = evJson.sources || [];
        return (
          <div style={{ background: '#FEF2F2', padding: '14px', borderRadius: '8px', border: '1px solid #FEE2E2' }}>
            <h4 style={{ color: '#B91C1C', fontSize: '13px', margin: '0 0 6px 0', fontWeight: '700' }}>
              High-Rate Flood Signature
            </h4>
            <p style={{ fontSize: '13px', margin: '0 0 8px 0', color: 'var(--cut-text-main)' }}>
              Volumetric surge in unestablished packets targeting a single host exceeding legitimate throughput baselines.
            </p>
            {sources.length > 0 && (
              <div>
                <span style={{ fontSize: '11px', fontWeight: '700', color: '#B91C1C' }}>Identified Participating Bot Sources:</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                  {sources.map((ip, i) => (
                    <span key={i} style={{ background: '#FEE2E2', color: '#DC2626', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace' }}>
                      {ip}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'Brute Force':
        return (
          <div style={{ background: '#FFFBEB', padding: '14px', borderRadius: '8px', border: '1px solid #FEF3C7' }}>
            <h4 style={{ color: '#B45309', fontSize: '13px', margin: '0 0 6px 0', fontWeight: '700' }}>
              Authentication Probe Pattern
            </h4>
            <p style={{ fontSize: '13px', margin: '0 0 8px 0', color: 'var(--cut-text-main)' }}>
              Repeated connection attempts to port <b>{event.destination_port || '22'}</b> with short-lived session durations.
            </p>
            <p style={{ fontSize: '12px', color: '#92400E', background: '#FEF9C3', padding: '8px', borderRadius: '6px', margin: 0 }}>
              <b>Note:</b> Encrypted web/SSH traffic does not normally reveal login failures to network sniffers; host authentication-server logs are recommended for definitive attribution.
            </p>
          </div>
        );

      case 'Deauthentication Flood':
      case 'Beacon Flood':
      case 'Probe Request Flood':
      case 'Authentication Flood':
      case 'Rogue AP / Evil Twin':
        return (
          <div style={{ background: '#FFFDF5', padding: '14px', borderRadius: '8px', border: '1px solid #FDE68A' }}>
            <h4 style={{ color: '#92400E', fontSize: '13px', margin: '0 0 6px 0', fontWeight: '700' }}>
              802.11 Wireless Frame Signature & Threshold Deviation
            </h4>
            <p style={{ fontSize: '13px', margin: '0 0 8px 0', color: 'var(--cut-text-main)' }}>
              {event.evidence || 'Anomalous wireless management frame frequency exceeding authorized campus baseline.'}
            </p>
            {event.bssid && (
              <div style={{ fontSize: '12px', fontFamily: 'monospace', color: '#78350F' }}>
                BSSID: {maskMAC(event.bssid)} | Channel: {event.channel || 'N/A'} | RSSI: {event.rssi_dbm || '—'} dBm
              </div>
            )}
          </div>
        );

      default:
        return (
          <div style={{ background: '#F8FAFC', padding: '14px', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
            <h4 style={{ color: '#475569', fontSize: '13px', margin: '0 0 6px 0', fontWeight: '700' }}>
              Detection Engine & Heuristic Evidence
            </h4>
            <p style={{ fontSize: '13px', margin: 0, color: 'var(--cut-text-main)' }}>
              {event.evidence || 'Traffic pattern differs from expected operational baseline or triggered custom rule threshold. Flagged for analyst triage.'}
            </p>
          </div>
        );
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '720px' }}>
        <div className="modal-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--cut-border)', padding: '16px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h3 style={{ fontSize: '17px', fontWeight: '800', color: 'var(--cut-blue-dark)', margin: 0 }}>
              Threat Detail: {event.event_id || `EVT-${event.id}`}
            </h3>
            <SeverityBadge severity={event.severity} />
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px' }}>
            <X size={20} color="#5A738E" />
          </button>
        </div>

        <div className="modal-body" style={{ padding: '20px', maxHeight: '70vh', overflowY: 'auto' }}>
          {actionNotice && (
            <div style={{ background: '#E0F2FE', color: '#0369A1', padding: '10px 14px', borderRadius: '6px', marginBottom: '16px', fontSize: '13px' }}>
              {actionNotice}
            </div>
          )}

          {/* Metadata Grid */}
          <div className="grid-fluid" style={{ '--cell-min': '200px', gap: '14px', marginBottom: '18px' }}>
            <div>
              <span style={{ fontSize: '12px', color: 'var(--cut-text-muted)' }}>Threat Classification</span>
              <p style={{ fontWeight: '700', fontSize: '15px', color: 'var(--cut-blue-dark)', margin: '2px 0 0 0' }}>{event.attack_type}</p>
            </div>
            <div>
              <span style={{ fontSize: '12px', color: 'var(--cut-text-muted)' }}>Detection Method</span>
              <p style={{ fontWeight: '600', fontSize: '14px', margin: '2px 0 0 0' }}>
                <span className="badge badge-info">{event.detection_method}</span> ({event.capture_source || 'Wireshark'})
              </p>
            </div>
            <div>
              <span style={{ fontSize: '12px', color: 'var(--cut-text-muted)' }}>Source Node</span>
              <p style={{ fontWeight: '600', fontFamily: 'monospace', fontSize: '13px', margin: '2px 0 0 0' }}>
                {event.source_ip ? `${event.source_ip}:${event.source_port || 0}` : maskMAC(event.source_mac) || '—'}
              </p>
            </div>
            <div>
              <span style={{ fontSize: '12px', color: 'var(--cut-text-muted)' }}>Destination Node</span>
              <p style={{ fontWeight: '600', fontFamily: 'monospace', fontSize: '13px', margin: '2px 0 0 0' }}>
                {event.destination_ip ? `${event.destination_ip}:${event.destination_port || 0}` : maskMAC(event.destination_mac) || '—'}
              </p>
            </div>
            {event.bssid && (
              <div>
                <span style={{ fontSize: '12px', color: 'var(--cut-text-muted)' }}>Wireless BSSID / Channel</span>
                <p style={{ fontWeight: '600', fontFamily: 'monospace', fontSize: '13px', margin: '2px 0 0 0' }}>
                  {maskMAC(event.bssid)} (Ch {event.channel || '—'})
                </p>
              </div>
            )}
            <div>
              <span style={{ fontSize: '12px', color: 'var(--cut-text-muted)' }}>Confidence Score</span>
              <p style={{ fontWeight: '700', fontSize: '14px', margin: '2px 0 0 0', color: event.confidence_score >= 0.85 ? '#16A34A' : '#D97706' }}>
                {event.confidence_score !== undefined && event.confidence_score !== null
                  ? `${(event.confidence_score * 100).toFixed(1)}%`
                  : 'Rule Threshold'}
              </p>
            </div>
            <div>
              <span style={{ fontSize: '12px', color: 'var(--cut-text-muted)' }}>Response Status</span>
              <p style={{ fontWeight: '600', fontSize: '14px', margin: '2px 0 0 0' }}>{event.response_status || 'Pending review'}</p>
            </div>
          </div>

          {/* Adaptive Evidence Section */}
          <div style={{ marginBottom: '18px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: '700', color: 'var(--cut-blue-dark)', margin: '0 0 8px 0' }}>
              Why It Was Flagged (Evidence & Heuristics)
            </h4>
            <p style={{ fontSize: '13px', color: 'var(--cut-text-main)', margin: '0 0 10px 0' }}>
              {event.evidence}
            </p>
            {renderAdaptiveEvidence()}
          </div>

          {/* Administrative Notes */}
          {event.notes && (
            <div style={{ marginBottom: '18px', background: '#F8FAFC', padding: '12px', borderRadius: '6px', border: '1px solid var(--cut-border)' }}>
              <h5 style={{ fontSize: '12px', fontWeight: '700', color: 'var(--cut-text-muted)', margin: '0 0 4px 0' }}>Analyst Case Notes:</h5>
              <pre style={{ fontSize: '12px', whiteSpace: 'pre-wrap', color: 'var(--cut-text-main)', margin: 0, fontFamily: 'inherit' }}>{event.notes}</pre>
            </div>
          )}

          {/* Add Note Button */}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setShowNotePrompt(true)}
            disabled={loading}
            icon={Send}
          >
            Add Investigator Note
          </Button>

          {/* Integrity Hash */}
          <div style={{ fontSize: '11px', color: '#94A3B8', fontFamily: 'monospace', marginTop: '16px' }}>
            SHA-256 Audit Integrity Hash: {event.integrity_hash || 'Computed on commit'}
          </div>
        </div>

        {/* Modal Triage Actions Footer */}
        <div className="modal-footer" style={{ borderTop: '1px solid var(--cut-border)', padding: '14px 20px', display: 'flex', gap: '8px', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleStatusChange('Acknowledged')}
            disabled={loading}
          >
            Acknowledge
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleStatusChange('Investigating')}
            disabled={loading}
          >
            Mark Investigating
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleStatusChange('False positive')}
            disabled={loading}
          >
            Mark False Positive
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => handleStatusChange('Resolved')}
            disabled={loading}
          >
            Resolve
          </Button>
        </div>
      </div>

      {showNotePrompt && (
        <PromptDialog
          isOpen={showNotePrompt}
          onClose={() => setShowNotePrompt(false)}
          onSubmit={handleAddNote}
          title="Add Investigator Note"
          placeholder="Enter your investigative notes or context..."
          defaultValue={noteText}
          multiline={true}
          maxLength={500}
          confirmText="Save Note"
          cancelText="Cancel"
        />
      )}
    </div>
  );
}
