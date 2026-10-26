
import React, { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import { getAlerts, getChains } from "../services/api";

function ChainGraph({ refreshKey }) {
  const graphRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    let cancelled = false;

    async function loadGraph() {
      try {
        const [alertData, chainData] = await Promise.all([
          getAlerts(),
          getChains()
        ]);

        if (cancelled || !graphRef.current) return;

        // Support both array responses and wrapped responses.
        const alerts = Array.isArray(alertData)
          ? alertData
          : alertData?.alerts || [];

        const chains = Array.isArray(chainData)
          ? chainData
          : chainData?.chains || [];

        const alertMap = new Map(
          alerts.map(alert => [String(alert.id), alert])
        );

        const elements = [];
        const addedNodes = new Set();

        // Add alert nodes referenced by the chains first.
        chains.forEach(chain => {
          let ids = [];

          try {
            ids = Array.isArray(chain.alert_ids)
              ? chain.alert_ids
              : JSON.parse(chain.alert_ids || "[]");
          } catch {
            console.error("Invalid alert_ids:", chain.alert_ids);
          }

          ids.forEach(id => {
            const key = String(id);
            const alert = alertMap.get(key);

            if (alert && !addedNodes.has(key)) {
              elements.push({
                data: {
                  id: `alert-${key}`,
                  label: `${alert.attack_type || "Alert"}\n${alert.source_ip || ""}`,
                  alertId: key
                }
              });
              addedNodes.add(key);
            }
          });

          // Connect the alerts in the recorded chain sequence.
          for (let i = 0; i < ids.length - 1; i++) {
            const sourceId = String(ids[i]);
            const targetId = String(ids[i + 1]);

            if (
              alertMap.has(sourceId) &&
              alertMap.has(targetId)
            ) {
              elements.push({
                data: {
                  id: `edge-${chain.chain_id}-${i}`,
                  source: `alert-${sourceId}`,
                  target: `alert-${targetId}`
                }
              });
            }
          }
        });

        // If there are no chains, still show available alerts.
        if (elements.length === 0) {
          alerts.forEach(alert => {
            const key = String(alert.id);

            elements.push({
              data: {
                id: `alert-${key}`,
                label: alert.attack_type || "Alert",
                alertId: key
              }
            });
          });
        }

        if (cyRef.current) {
          cyRef.current.destroy();
          cyRef.current = null;
        }

        cyRef.current = cytoscape({
          container: graphRef.current,
          elements,
          style: [
            {
              selector: "node",
              style: {
                "background-color": "#2563eb",
                "label": "data(label)",
                "color": "#ffffff",
                "text-valign": "center",
                "text-halign": "center",
                "font-size": "10px",
                "text-wrap": "wrap",
                "text-max-width": "100px",
                "width": "85px",
                "height": "85px",
                "border-width": 2,
                "border-color": "#ffffff"
              }
            },
            {
              selector: "edge",
              style: {
                "width": 3,
                "line-color": "#94a3b8",
                "target-arrow-color": "#94a3b8",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier"
              }
            }
          ],
          layout: {
            name: "breadthfirst",
            directed: true,
            padding: 40,
            spacingFactor: 1.5
          }
        });

        if (elements.length === 0) {
          graphRef.current.innerHTML =
            "No alerts or attack-chain data available.";
        }

        cyRef.current.on("tap", "node", event => {
          console.log("Selected alert:", event.target.data());
        });

      } catch (error) {
        console.error("Failed to load attack chain graph:", error);
      }
    }

    loadGraph();

    return () => {
      cancelled = true;

      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [refreshKey]);

  return (
    <div
      style={{
        width: "100%",
        minHeight: "500px",
        background: "#111827",
        borderRadius: "10px",
        padding: "10px",
        boxSizing: "border-box",
        color: "white"
      }}
    >
      <h2>Attack Chain Graph</h2>
      <div
        ref={graphRef}
        style={{
          width: "100%",
          height: "420px",
          position: "relative"
        }}
      />
    </div>
  );
}

export default ChainGraph;
