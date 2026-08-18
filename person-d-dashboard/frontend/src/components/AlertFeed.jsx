import React, { useEffect, useState } from "react";
import { getAlerts } from "../services/api";


function AlertFeed({ refreshKey }) {

  const [alerts, setAlerts] = useState([]);

  const [loading, setLoading] =
    useState(true);


  useEffect(() => {

    async function loadAlerts() {

      try {

        const data = await getAlerts();

        setAlerts(data.alerts || []);

      } catch (error) {

        console.error(
          "Failed to load alerts:",
          error
        );

      } finally {

        setLoading(false);
      }

    }

    loadAlerts();

  }, [refreshKey]);


  if (loading) {

    return (
      <div style={cardStyle}>
        <h2>Security Alerts</h2>
        <p>Loading alerts...</p>
      </div>
    );

  }


  return (

    <div style={cardStyle}>

      <h2>
        Security Alerts
      </h2>


      {alerts.length === 0 ? (

        <p>
          No alerts available.
        </p>

      ) : (

        alerts.map((alert) => (

          <div
            key={alert.id}
            style={{
              border: "1px solid #374151",
              borderRadius: "8px",
              padding: "12px",
              marginBottom: "10px",
              background: "#1f2937"
            }}
          >

            <div
              style={{
                display: "flex",
                justifyContent: "space-between"
              }}
            >

              <strong>
                {alert.attack_type}
              </strong>

              <span>
                {alert.mitre_tactic || "Unknown tactic"}
              </span>

            </div>


            <p>
              Source: {alert.source_ip}
            </p>


            <p>
              Target IP: {alert.target_ip}
            </p>


            <p>
              Target Node: {alert.target_node || "-"}
            </p>


            <p>
              Detection:
              {" "}
              {alert.detection_source}
            </p>


            <p>
              Time:
              {" "}
              {alert.timestamp}
            </p>

          </div>

        ))

      )}

    </div>

  );

}


const cardStyle = {
  background: "#111827",
  color: "white",
  borderRadius: "10px",
  padding: "20px",
  marginTop: "20px"
};


export default AlertFeed;