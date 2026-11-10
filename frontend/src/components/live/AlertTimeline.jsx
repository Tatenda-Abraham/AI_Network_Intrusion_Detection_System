import React, { useEffect, useRef } from 'react';
import Chart from 'chart.js/auto';

export default function AlertTimeline({ alertData }) {
  const chartRef = useRef(null);
  const chartInstance = useRef(null);

  useEffect(() => {
    if (!chartRef.current) return;

    if (chartInstance.current) {
      chartInstance.current.destroy();
    }

    const ctx = chartRef.current.getContext('2d');
    chartInstance.current = new Chart(ctx, {
      type: 'line',
      data: {
        labels: alertData.labels, // last 60 minutes
        datasets: [
          {
            label: 'Alerts',
            data: alertData.counts,
            borderColor: '#D4AF37',
            backgroundColor: 'rgba(212, 175, 55, 0.1)',
            fill: true,
            tension: 0.4,
            pointRadius: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            mode: 'index',
            intersect: false
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: { stepSize: 1, color: '#94A3B8', font: { size: 10 } },
            grid: { color: '#F1F5F9' }
          },
          x: {
            ticks: { color: '#94A3B8', font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 12 },
            grid: { display: false }
          }
        }
      }
    });

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [alertData]);

  return (
    <div className="card panel-short" style={{ padding: '15px' }}>
      <h3 style={{ margin: '0 0 10px 0', fontSize: '13px', fontWeight: '700', color: '#64748B' }}>
        60-Minute Alert Timeline
      </h3>
      <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
        <canvas ref={chartRef}></canvas>
      </div>
    </div>
  );
}
