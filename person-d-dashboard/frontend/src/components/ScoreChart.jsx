import React, {
  useEffect,
  useState
} from "react";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from "recharts";

import {
  getScores
} from "../services/api";


function ScoreChart({ refreshKey }) {

  const [scores, setScores] =
    useState([]);

  const [loading, setLoading] =
    useState(true);


  useEffect(() => {

    async function loadScores() {

      try {

        const data =
          await getScores();


        const formattedScores =
          (data.scores || []).map(
            (item) => ({

              time:
                item.timestamp,

              score:
                Number(item.score),

              chain_id:
                item.chain_id,

              severity:
                item.severity_label

            })
          );


        setScores(
          formattedScores
        );


      } catch (error) {

        console.error(
          "Failed to load scores:",
          error
        );

      } finally {

        setLoading(false);

      }

    }


    loadScores();

  }, [refreshKey]);


  if (loading) {

    return (
      <div style={cardStyle}>
        <h2>
          Threat Score Trend
        </h2>

        <p>
          Loading threat scores...
        </p>
      </div>
    );

  }


  return (

    <div style={cardStyle}>

      <h2>
        Threat Score Trend
      </h2>


      {scores.length === 0 ? (

        <p>
          No threat scores available.
        </p>

      ) : (

        <ResponsiveContainer
          width="100%"
          height={400}
        >

          <LineChart
            data={scores}
            margin={{
              top: 10,
              right: 30,
              left: 10,
              bottom: 20
            }}
          >

            <CartesianGrid
              strokeDasharray="3 3"
            />

            <XAxis
              dataKey="time"
            />

            <YAxis
              domain={[0, 100]}
            />

            <Tooltip />

            <Legend />


            <Line
              type="monotone"
              dataKey="score"
              name="Threat Score"
              stroke="#22c55e"
              strokeWidth={3}
              dot={{ r: 5 }}
              activeDot={{ r: 7 }}
            />

          </LineChart>

        </ResponsiveContainer>

      )}

    </div>

  );

}


const cardStyle = {

  width: "100%",

  minHeight: "450px",

  background: "#111827",

  color: "white",

  borderRadius: "10px",

  padding: "20px",

  boxSizing: "border-box"

};


export default ScoreChart;