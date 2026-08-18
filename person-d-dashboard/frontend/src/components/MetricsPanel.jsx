import React, {
  useEffect,
  useState
} from "react";

import {
  getMetrics
} from "../services/api";


function MetricsPanel({ refreshKey }) {

  const [metrics, setMetrics] =
    useState(null);

  const [loading, setLoading] =
    useState(true);


  useEffect(() => {

    async function loadMetrics() {

      try {

        const data =
          await getMetrics();

        setMetrics(data);

      } catch (error) {

        console.error(
          "Failed to load metrics:",
          error
        );

      } finally {

        setLoading(false);

      }

    }


    loadMetrics();

  }, [refreshKey]);


  if (loading) {

    return (
      <div style={cardStyle}>

        <h2>
          Evaluation Metrics
        </h2>

        <p>
          Loading metrics...
        </p>

      </div>
    );

  }


  if (!metrics) {

    return (
      <div style={cardStyle}>

        <h2>
          Evaluation Metrics
        </h2>

        <p>
          No metrics available.
        </p>

      </div>
    );

  }


  const confidence =
    metrics.average_ml_confidence == null
      ? "-"
      : `${(
          Number(
            metrics.average_ml_confidence
          ) * 100
        ).toFixed(1)}%`;


  return (

    <div style={cardStyle}>

      <h2>
        Evaluation Metrics
      </h2>


      <div
        style={{
          display: "grid",

          gridTemplateColumns:
            "repeat(auto-fit, minmax(180px, 1fr))",

          gap: "15px",

          marginTop: "20px"
        }}
      >

        <MetricCard
          title="Total Alerts"
          value={
            metrics.total_alerts ?? 0
          }
        />


        <MetricCard
          title="Attack Chains"
          value={
            metrics.total_chains ?? 0
          }
        />


        <MetricCard
          title="Responses"
          value={
            metrics.total_responses ?? 0
          }
        />


        <MetricCard
          title="Avg ML Confidence"
          value={confidence}
        />

      </div>

    </div>

  );

}


function MetricCard({
  title,
  value
}) {

  return (

    <div
      style={{
        background: "#1f2937",
        borderRadius: "8px",
        padding: "20px"
      }}
    >

      <p
        style={{
          margin: 0,
          color: "#9ca3af"
        }}
      >
        {title}
      </p>


      <h2
        style={{
          marginTop: "10px",
          marginBottom: 0,
          color: "white"
        }}
      >
        {value}
      </h2>

    </div>

  );

}


const cardStyle = {

  background: "#111827",

  borderRadius: "10px",

  padding: "20px",

  marginTop: "20px",

  color: "white"

};


export default MetricsPanel;