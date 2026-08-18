import React, { useEffect, useState } from "react";


const API_URL =
  process.env.REACT_APP_API_URL ||
  "http://localhost:8000";


function NodeHealth({ refreshKey }) {

  const [nodes, setNodes] = useState([]);

  const [loading, setLoading] =
    useState(true);


  useEffect(() => {

    async function loadNodeHealth() {

      try {

        const response =
          await fetch(`${API_URL}/node-health`);


        if (!response.ok) {
          throw new Error(
            `Request failed: ${response.status}`
          );
        }


        const data =
          await response.json();


        setNodes(
          data.nodes || []
        );


      } catch (error) {

        console.error(
          "Failed to load node health:",
          error
        );

      } finally {

        setLoading(false);

      }

    }


    loadNodeHealth();

  }, [refreshKey]);


  if (loading) {

    return (
      <div style={cardStyle}>
        <h2>Node Health</h2>
        <p>Loading node health...</p>
      </div>
    );

  }


  return (

    <div style={cardStyle}>

      <h2>
        Edge Node Health
      </h2>


      {nodes.length === 0 ? (

        <p>
          No node health data available.
        </p>

      ) : (

        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "repeat(auto-fit, minmax(180px, 1fr))",
            gap: "15px",
            marginTop: "20px"
          }}
        >

          {nodes.map((node) => (

            <div
              key={node.id || node.node_name}
              style={{
                background:
                  getStatusBackground(
                    node.status
                  ),

                borderRadius: "10px",

                padding: "20px",

                color: "white"
              }}
            >

              <h3>
                {node.node_name}
              </h3>


              <p>
                Status:
                {" "}
                <strong>
                  {node.status}
                </strong>
              </p>


              <p>
                CPU:
                {" "}
                {node.cpu_usage ?? "-"}%
              </p>


              <p>
                Memory:
                {" "}
                {node.memory_usage ?? "-"}%
              </p>


              <small>
                Updated:
                {" "}
                {node.last_updated || "-"}
              </small>

            </div>

          ))}

        </div>

      )}

    </div>

  );

}


function getStatusBackground(status) {

  const value =
    String(status || "")
      .toLowerCase();


  if (value === "healthy") {
    return "#166534";
  }


  if (
    value === "monitoring" ||
    value === "monitored"
  ) {
    return "#92400e";
  }


  if (value === "isolated") {
    return "#991b1b";
  }


  return "#374151";
}


const cardStyle = {

  background: "#111827",

  color: "white",

  borderRadius: "10px",

  padding: "20px",

  marginTop: "20px"

};


export default NodeHealth;