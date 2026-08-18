import React, {
  useEffect,
  useState
} from "react";

import {
  getResponses
} from "../services/api";


function ResponseLog({ refreshKey }) {

  const [responses, setResponses] =
    useState([]);

  const [loading, setLoading] =
    useState(true);


  useEffect(() => {

    async function loadResponses() {

      try {

        const data =
          await getResponses();

        setResponses(
          data.responses || []
        );

      } catch (error) {

        console.error(
          "Failed to load responses:",
          error
        );

      } finally {

        setLoading(false);

      }

    }


    loadResponses();

  }, [refreshKey]);


  if (loading) {

    return (
      <div style={cardStyle}>

        <h2>
          Response Audit Log
        </h2>

        <p>
          Loading responses...
        </p>

      </div>
    );

  }


  return (

    <div style={cardStyle}>

      <h2>
        Response Audit Log
      </h2>


      {responses.length === 0 ? (

        <p>
          No responses available.
        </p>

      ) : (

        <div
          style={{
            overflowX: "auto"
          }}
        >

          <table
            style={{
              width: "100%",
              borderCollapse:
                "collapse"
            }}
          >

            <thead>

              <tr>

                <th style={headerStyle}>
                  Time
                </th>

                <th style={headerStyle}>
                  Action
                </th>

                <th style={headerStyle}>
                  Target
                </th>

                <th style={headerStyle}>
                  Status
                </th>

                <th style={headerStyle}>
                  Rollback
                </th>

                <th style={headerStyle}>
                  Rolled Back At
                </th>

              </tr>

            </thead>


            <tbody>

              {responses.map(
                (response) => (

                  <tr
                    key={response.id}
                  >

                    <td style={cellStyle}>
                      {response.timestamp}
                    </td>

                    <td style={cellStyle}>
                      {response.action_type}
                    </td>

                    <td style={cellStyle}>
                      {response.target}
                    </td>

                    <td style={cellStyle}>

                      <span
                        style={{
                          padding:
                            "5px 10px",

                          borderRadius:
                            "12px",

                          background:
                            response.status ===
                            "rolled_back"
                              ? "#92400e"
                              : "#166534"
                        }}
                      >
                        {response.status}
                      </span>

                    </td>

                    <td style={cellStyle}>
                      {response.rollback_command ||
                        "-"}
                    </td>

                    <td style={cellStyle}>
                      {response.rolled_back_at ||
                        "-"}
                    </td>

                  </tr>

                )
              )}

            </tbody>

          </table>

        </div>

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


const headerStyle = {

  textAlign: "left",

  padding: "12px",

  borderBottom:
    "1px solid #374151"

};


const cellStyle = {

  padding: "12px",

  borderBottom:
    "1px solid #374151"

};


export default ResponseLog;