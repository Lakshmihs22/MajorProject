const WS_URL = process.env.REACT_APP_WS_URL || "ws://localhost:8000/ws";

// Opens a WebSocket and reconnects automatically after an unexpected disconnect.
// Call the returned cleanup function when the component unmounts.
export function connectWebSocket(onMessage, onStatusChange) {
  let socket = null;
  let retryTimer = null;
  let manuallyClosed = false;
  let retryDelay = 1000;

  const setStatus = (status) => {
    if (onStatusChange) onStatusChange(status);
  };

  const connect = () => {
    if (manuallyClosed) return;
    try {
      socket = new WebSocket(WS_URL);
    } catch (error) {
      setStatus("disconnected");
      scheduleReconnect();
      return;
    }

    socket.onopen = () => {
      retryDelay = 1000;
      setStatus("connected");
    };
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.event_type === "CONNECTION_STATUS") {
          // Browser WebSocket status is separate from Redis event-bus status.
          if (onMessage) onMessage(data);
          return;
        }
        if (onMessage) onMessage(data);
      } catch (error) {
        console.error("[WebSocket] Invalid message:", error);
      }
    };
    socket.onerror = () => setStatus("error");
    socket.onclose = () => {
      setStatus("disconnected");
      scheduleReconnect();
    };
  };

  const scheduleReconnect = () => {
    if (manuallyClosed || retryTimer) return;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      connect();
      retryDelay = Math.min(retryDelay * 2, 15000);
    }, retryDelay);
  };

  connect();
  return () => {
    manuallyClosed = true;
    if (retryTimer) clearTimeout(retryTimer);
    if (socket) socket.close();
  };
}
