"""
Canonical edge device metadata for Person C policy / seeding and dashboard fleet views.
IPs match docker-compose static addresses on edgeshield-net.
"""

EDGE_DEVICES = {
    "172.28.0.11": {
        "node_name": "edge-node-1",
        "criticality": "high",
        "device_class": "industrial_opc_gateway",
        "display_name": "Industrial OPC-UA Gateway",
        "description": "PLC gateway",
    },
    "172.28.0.12": {
        "node_name": "edge-node-2",
        "criticality": "medium",
        "device_class": "iot_sensor_hub",
        "display_name": "IoT Sensor Hub",
        "description": "IoT hub",
    },
    "172.28.0.13": {
        "node_name": "edge-node-3",
        "criticality": "critical",
        "device_class": "dns_utility_edge",
        "display_name": "DNS Utility Edge",
        "description": "DNS edge",
    },
}