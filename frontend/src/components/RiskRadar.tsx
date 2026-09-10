interface BreakdownProps {
  breakdown: Record<string, number>;
  riskLevel: string;
}

export default function RiskRadar({ breakdown, riskLevel }: BreakdownProps) {
  if (!breakdown || Object.keys(breakdown).length === 0) return null;

  const getBarColor = (val: number) => {
    if (val >= 60) return '#ef4444';
    if (val >= 30) return '#f97316';
    if (val >= 15) return '#eab308';
    return '#10b981';
  };

  return (
    <div className="mt-3">
      <h6 className="text-muted text-uppercase small mb-3" style={{ letterSpacing: '0.05em' }}>
        <i className="fas fa-chart-bar me-2"></i> Risk Signal Weight Breakdown
      </h6>
      <div className="d-flex flex-column gap-3">
        {Object.entries(breakdown).map(([signal, score]) => {
          const val = Math.min(100, Math.max(0, Number(score)));
          const color = getBarColor(val);
          const label = signal.replace(/_/g, ' ').replace(/\w/g, (l) => l.toUpperCase());

          return (
            <div key={signal}>
              <div className="d-flex justify-content-between align-items-center mb-1">
                <span className="small font-monospace text-light">{label}</span>
                <span className="small font-monospace fw-bold" style={{ color }}>
                  {val.toFixed(1)} / 100
                </span>
              </div>
              <div
                className="progress"
                style={{ height: '6px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '4px' }}
              >
                <div
                  className="progress-bar"
                  role="progressbar"
                  style={{
                    width: `${val}%`,
                    backgroundColor: color,
                    boxShadow: `0 0 8px ${color}`,
                    borderRadius: '4px',
                    transition: 'width 0.6s ease',
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
