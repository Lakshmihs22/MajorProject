import React, {
  useEffect,
  useRef
} from "react";

import cytoscape from "cytoscape";

import {
  getAlerts,
  getChains
} from "../services/api";


function ChainGraph({ refreshKey }) {

  const graphRef = useRef(null);

  const cyRef = useRef(null);


  useEffect(() => {

    async function loadGraph() {

      try {

        const [
          alertData,
          chainData
        ] = await Promise.all([

          getAlerts(),

          getChains()

        ]);


        const alerts =
          alertData.alerts || [];

        const chains =
          chainData.chains || [];


        const elements = [];


        /*
         * Create graph nodes
         */

        alerts.forEach((alert) => {

          elements.push({

            data: {

              id:
                `alert-${alert.id}`,

              label:
                alert.attack_type,

              severity:
                alert.severity_label ||
                alert.severity ||
                "Unknown",

              source:
                alert.source_ip,

              target:
                alert.target_node,

              tactic:
                alert.mitre_tactic || ""

            }

          });

        });


        /*
         * Create edges from
         * attack_chains.alert_ids
         */

        chains.forEach((chain) => {

          let alertIds = [];


          try {

            alertIds =
              JSON.parse(
                chain.alert_ids || "[]"
              );

          } catch (error) {

            console.error(
              "Invalid alert_ids:",
              chain.alert_ids
            );

          }


          for (
            let i = 0;
            i < alertIds.length - 1;
            i++
          ) {

            elements.push({

              data: {

                id:
                  `edge-${chain.chain_id}-${i}`,

                source:
                  `alert-${alertIds[i]}`,

                target:
                  `alert-${alertIds[i + 1]}`

              }

            });

          }

        });


        /*
         * Destroy old graph
         */

        if (cyRef.current) {

          cyRef.current.destroy();

        }


        /*
         * Create Cytoscape graph
         */

        cyRef.current =
          cytoscape({

            container:
              graphRef.current,

            elements,

            style: [

              {
                selector: "node",

                style: {

                  "background-color":
                    "#2563eb",

                  "label":
                    "data(label)",

                  "color":
                    "#ffffff",

                  "text-valign":
                    "center",

                  "text-halign":
                    "center",

                  "font-size":
                    "12px",

                  "width":
                    "70px",

                  "height":
                    "70px",

                  "border-width":
                    "2px",

                  "border-color":
                    "#ffffff"

                }

              },

              {
                selector: "edge",

                style: {

                  "width":
                    3,

                  "line-color":
                    "#94a3b8",

                  "target-arrow-color":
                    "#94a3b8",

                  "target-arrow-shape":
                    "triangle",

                  "curve-style":
                    "bezier"

                }

              }

            ],

            layout: {

              name:
                "breadthfirst",

              directed:
                true,

              padding:
                50,

              spacingFactor:
                1.5

            }

          });


        /*
         * Node click
         */

        cyRef.current.on(
          "tap",
          "node",
          (event) => {

            console.log(
              "Selected alert:",
              event.target.data()
            );

          }
        );


      } catch (error) {

        console.error(
          "Failed to load attack chain graph:",
          error
        );

      }

    }


    loadGraph();


    return () => {

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
        height: "500px",
        background: "#111827",
        borderRadius: "10px",
        padding: "10px",
        boxSizing: "border-box",
        color: "white"
      }}
    >

      <h2>
        Attack Chain Graph
      </h2>


      <div
        ref={graphRef}
        style={{
          width: "100%",
          height: "420px"
        }}
      />

    </div>

  );

}


export default ChainGraph;