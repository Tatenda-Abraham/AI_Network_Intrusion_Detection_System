import React from 'react';
import { ChevronUp, ChevronDown, ArrowUpDown, ChevronLeft, ChevronRight, Inbox, RotateCcw } from 'lucide-react';
import Button from './Button';

export default function Table({
  columns = [], // array of { key, header, sortable, render, width, align }
  data = [],
  loading = false,
  error = null,
  onRetry,
  sortBy,
  sortDirection = 'desc', // 'asc' or 'desc'
  onSort,
  pagination = null, // { page, totalPages, totalItems, pageSize, onPageChange, onPageSizeChange }
  emptyMessage = 'No telemetry records found.',
  emptyActionText,
  onEmptyAction,
  className = '',
  style = {}
}) {
  return (
    <div
      className={`ui-table-container ${className}`}
      style={{
        background: '#FFFFFF',
        borderRadius: '10px',
        border: '1px solid var(--cut-border, #CBD5E1)',
        boxShadow: '0 1px 3px rgba(0,0,0,0.03)',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        ...style
      }}
    >
      <div style={{ overflowX: 'auto', width: '100%' }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            textAlign: 'left',
            fontSize: '13.5px'
          }}
        >
          <thead>
            <tr
              style={{
                background: '#F8FAFC',
                borderBottom: '1px solid #E2E8F0',
                position: 'sticky',
                top: 0,
                zIndex: 2
              }}
            >
              {columns.map((col) => {
                const isCurrentSort = sortBy === col.key;
                const canSort = col.sortable && onSort;

                return (
                  <th
                    key={col.key}
                    onClick={() => canSort && onSort(col.key)}
                    style={{
                      padding: '12px 16px',
                      fontSize: '12px',
                      fontWeight: '700',
                      color: isCurrentSort ? 'var(--cut-blue-primary, #0288D1)' : '#475569',
                      textTransform: 'uppercase',
                      letterSpacing: '0.4px',
                      cursor: canSort ? 'pointer' : 'default',
                      userSelect: 'none',
                      width: col.width,
                      textAlign: col.align || 'left',
                      whiteSpace: 'nowrap'
                    }}
                  >
                    <div
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        justifyContent: col.align === 'right' ? 'flex-end' : (col.align === 'center' ? 'center' : 'flex-start')
                      }}
                    >
                      <span>{col.header}</span>
                      {canSort && (
                        isCurrentSort ? (
                          sortDirection === 'asc' ? <ChevronUp size={14} /> : <ChevronDown size={14} />
                        ) : (
                          <ArrowUpDown size={13} style={{ color: '#94A3B8' }} />
                        )
                      )}
                    </div>
                  </th>
                );
              })}
            </tr>
          </thead>

          <tbody>
            {loading ? (
              // Loading skeleton rows
              Array.from({ length: 5 }).map((_, rIdx) => (
                <tr key={rIdx} style={{ borderBottom: '1px solid #F1F5F9' }}>
                  {columns.map((col, cIdx) => (
                    <td key={cIdx} style={{ padding: '14px 16px' }}>
                      <div
                        style={{
                          height: '16px',
                          background: '#E2E8F0',
                          borderRadius: '4px',
                          width: `${50 + ((cIdx * 17) % 45)}%`,
                          animation: 'pulse 1.5s infinite ease-in-out'
                        }}
                      />
                    </td>
                  ))}
                </tr>
              ))
            ) : error ? (
              // Error state with retry
              <tr>
                <td colSpan={columns.length} style={{ padding: '48px 20px', textAlign: 'center' }}>
                  <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                    <p style={{ color: '#DC2626', fontSize: '14px', fontWeight: '600', margin: 0 }}>
                      {error}
                    </p>
                    {onRetry && (
                      <Button variant="secondary" size="sm" onClick={onRetry} icon={RotateCcw}>
                        Retry Loading
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ) : data.length === 0 ? (
              // Empty state
              <tr>
                <td colSpan={columns.length} style={{ padding: '48px 20px', textAlign: 'center' }}>
                  <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                    <Inbox size={42} color="#94A3B8" />
                    <p style={{ fontSize: '14px', color: '#64748B', margin: 0 }}>
                      {emptyMessage}
                    </p>
                    {emptyActionText && onEmptyAction && (
                      <Button variant="primary" size="sm" onClick={onEmptyAction} style={{ marginTop: '6px' }}>
                        {emptyActionText}
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              // Real data rows with zebra/hover effect
              data.map((row, rIdx) => (
                <tr
                  key={row.id ?? rIdx}
                  className="ui-table-row"
                  style={{
                    borderBottom: '1px solid #F1F5F9',
                    background: rIdx % 2 === 0 ? '#FFFFFF' : '#FAFAFA',
                    transition: 'background-color 0.1s ease'
                  }}
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      style={{
                        padding: '12px 16px',
                        color: '#1E293B',
                        textAlign: col.align || 'left',
                        whiteSpace: col.nowrap ? 'nowrap' : 'normal'
                      }}
                    >
                      {col.render ? col.render(row[col.key], row, rIdx) : (row[col.key] ?? '—')}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar */}
      {pagination && pagination.totalPages > 0 && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 16px',
            background: '#F8FAFC',
            borderTop: '1px solid #E2E8F0',
            flexWrap: 'wrap',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {pagination.totalItems !== undefined && (
              <span style={{ fontSize: '12.5px', color: '#64748B' }}>
                Page <b>{pagination.page}</b> of <b>{pagination.totalPages}</b> ({pagination.totalItems.toLocaleString()} total items)
              </span>
            )}

            {pagination.onPageSizeChange && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginLeft: '12px' }}>
                <span style={{ fontSize: '12px', color: '#64748B' }}>Rows:</span>
                <select
                  value={pagination.pageSize || 25}
                  onChange={(e) => pagination.onPageSizeChange(Number(e.target.value))}
                  style={{
                    height: '28px',
                    borderRadius: '5px',
                    border: '1px solid #CBD5E1',
                    fontSize: '12px',
                    padding: '0 6px',
                    background: '#FFFFFF',
                    color: '#1E293B',
                    outline: 'none'
                  }}
                >
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Button
              variant="secondary"
              size="sm"
              disabled={pagination.page <= 1 || loading}
              onClick={() => pagination.onPageChange(pagination.page - 1)}
              icon={ChevronLeft}
              ariaLabel="Previous page"
            />
            <span style={{ fontSize: '12.5px', fontWeight: '600', color: '#1E293B', padding: '0 8px' }}>
              {pagination.page}
            </span>
            <Button
              variant="secondary"
              size="sm"
              disabled={pagination.page >= pagination.totalPages || loading}
              onClick={() => pagination.onPageChange(pagination.page + 1)}
              icon={ChevronRight}
              ariaLabel="Next page"
            />
          </div>
        </div>
      )}
    </div>
  );
}
