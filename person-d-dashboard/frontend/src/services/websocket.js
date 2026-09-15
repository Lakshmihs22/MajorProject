const WS_URL =
  process.env.REACT_APP_WS_URL ||
  "ws://localhost:8000/ws";


export function connectWebSocket(
  onMessage,
  onStatusChange
) {

  const socket =
    new WebSocket(WS_URL);


  socket.onopen = () => {

    console.log(
      "[WebSocket] Connected"
    );


    if (onStatusChange) {

      onStatusChange(
        "connected"
      );

    }

  };


  socket.onmessage = (event) => {

    try {

      const data =
        JSON.parse(
          event.data
        );


      console.log(
        "[WebSocket] Event:",
        data
      );


      if (onMessage) {

        onMessage(data);

      }

    } catch (error) {

      console.error(
        "[WebSocket] Invalid message:",
        error
      );

    }

  };


  socket.onerror = (error) => {

    console.error(
      "[WebSocket] Error:",
      error
    );


    if (onStatusChange) {

      onStatusChange(
        "error"
      );

    }

  };


  socket.onclose = () => {

    console.log(
      "[WebSocket] Disconnected"
    );


    if (onStatusChange) {

      onStatusChange(
        "disconnected"
      );

    }

  };


  return socket;

}