import React from "react";

// Placeholder dashboard shell. Real components to build:
//   - AlertFeed (last 50 alerts, color-coded by severity)
//   - ChainGraph (Cytoscape.js force-directed graph of correlated alerts)
//   - ScoreTrend (Recharts line per active chain)
//   - NodeHealthMatrix (green/amber/red tiles for the 3 edge nodes)
//   - ResponseAuditLog (Defender Agent actions + rollback status)
//   - MetricsPanel (F1, precision, recall, false positive rate)
export default function App() {
  return (
    <div style={{ fontFamily: "sans-serif", padding: "2rem" }}>
      <h1>EdgeShield Dashboard</h1>
      <p>Placeholder shell -- components come after the backend has real data.</p>
    </div>
  );
}
