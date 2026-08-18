const API_URL =
  process.env.REACT_APP_API_URL ||
  "http://localhost:8000";


async function fetchData(endpoint) {

  const response =
    await fetch(
      `${API_URL}${endpoint}`
    );


  if (!response.ok) {

    throw new Error(
      `API request failed: ${response.status}`
    );

  }


  return response.json();

}


export function getAlerts() {
  return fetchData("/alerts");
}


export function getChains() {
  return fetchData("/chains");
}


export function getScores() {
  return fetchData("/scores");
}


export function getResponses() {
  return fetchData("/responses");
}


export function getMetrics() {
  return fetchData("/metrics");
}


export function getHealth() {
  return fetchData("/health");
}