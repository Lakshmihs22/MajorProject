import React from "react";


function LiveConnection({ status }) {

  let statusText =
    "Connecting...";


  if (status === "connected") {

    statusText =
      "Live Connection: 🟢 Connected";

  }


  if (status === "disconnected") {

    statusText =
      "Live Connection: 🔴 Disconnected";

  }


  if (status === "error") {

    statusText =
      "Live Connection: ⚠️ Error";

  }


  return (

    <div
      style={{
        background: "#1f2937",

        color: "white",

        padding: "10px 15px",

        borderRadius: "8px",

        marginBottom: "20px",

        display: "inline-block"
      }}
    >

      {statusText}

    </div>

  );

}


export default LiveConnection;