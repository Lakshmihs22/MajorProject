import React, { useEffect, useState } from "react";

import AlertFeed from "./components/AlertFeed";
import ChainGraph from "./components/ChainGraph";
import ScoreChart from "./components/ScoreChart";
import NodeHealth from "./components/NodeHealth";
import ResponseLog from "./components/ResponseLog";
import MetricsPanel from "./components/MetricsPanel";
import LiveConnection from "./components/LiveConnection";

import { connectWebSocket } from "./services/websocket";


function App() {

  const [liveEvents, setLiveEvents] = useState([]);

  const [connectionStatus, setConnectionStatus] =
    useState("connecting");

  const [refreshKey, setRefreshKey] = useState(0);


  /*
   * Connect to FastAPI WebSocket
   */

  useEffect(() => {

    const socket = connectWebSocket(

      (event) => {

        console.log(
          "[App] Received live event:",
          event
        );


        setLiveEvents((previousEvents) => [

          ...previousEvents.slice(-49),

          {
            ...event,
            receivedAt:
              new Date().toISOString()
          }

        ]);


        /*
         * Every new event tells the
         * dashboard to reload database data.
         */

        setRefreshKey(
          (previous) => previous + 1
        );

      },


      (status) => {

        setConnectionStatus(status);

      }

    );


    /*
     * Close WebSocket when component
     * is removed.
     */

    return () => {

      socket.close();

    };

  }, []);


  return (

    <div
      style={{
        minHeight: "100vh",
        background: "#0f172a",
        padding: "20px",
        boxSizing: "border-box"
      }}
    >

      {/* TITLE */}

      <h1
        style={{
          color: "white",
          marginBottom: "10px"
        }}
      >
        EdgeShield Dashboard
      </h1>


      {/* LIVE CONNECTION */}

      <LiveConnection
        status={connectionStatus}
      />


      {/* LIVE EVENT COUNT */}

      <p
        style={{
          color: "#9ca3af",
          marginBottom: "25px"
        }}
      >
        Live events received: {liveEvents.length}
      </p>


      {/* NODE HEALTH */}

      <NodeHealth
        refreshKey={refreshKey}
      />


      <br />


      {/* ATTACK CHAIN GRAPH */}

      <ChainGraph
        refreshKey={refreshKey}
      />


      <br />


      {/* THREAT SCORE */}

      <ScoreChart
        refreshKey={refreshKey}
      />


      <br />


      {/* DEFENDER RESPONSE LOG */}

      <ResponseLog
        refreshKey={refreshKey}
      />


      <br />


      {/* EVALUATION METRICS */}

      <MetricsPanel
        refreshKey={refreshKey}
      />


      <br />


      {/* SECURITY ALERTS */}

      <AlertFeed
        refreshKey={refreshKey}
      />

    </div>

  );

}


export default App;