[← Back to the README](../README.md)

# Prometheus & Grafana

`GET /metrics` serves Prometheus metrics, including:
- devices active by kind and type
- clients per AP and per SSID
- presence and signal of watched or labelled devices, and group presence
- events per type, open findings by severity
- LoRa nodes and frames per protocol, LoRa airtime, Zigbee radios and networks
- channel airtime and retry ratios, radar hits per DFS channel (`sniffowireless_dfs_radar_24h`) and DFS events (`sniffowireless_dfs_events_total`)
- sensor frames/s, and store queue/drops
- the version and commit of the server (`sniffowireless_build_info`), and the load (`sniffowireless_sensor_load1`) and memory use share (`sniffowireless_sensor_memory_used_ratio`) of each remote sensor that is reporting

Create a token with scope `metrics` and scrape with it:

```yaml
scrape_configs:
  - job_name: sniffowireless
    authorization: { type: Bearer, credentials_file: /etc/prometheus/sniffowireless_token }
    static_configs: [{ targets: ["sniffowireless-host:8080"] }]
```

`contrib/monitoring/` holds a ready-to-run Prometheus + Grafana stack with a provisioned **sniffowireless** dashboard (including LoRa nodes, frames and airtime, and Zigbee radios and networks):

```bash
echo -n "sniffowireless_<your metrics token>" > contrib/monitoring/sniffowireless_token
GRAFANA_PASSWORD=choose-one docker compose -f contrib/monitoring/docker-compose.monitoring.yml up -d
# Grafana: http://<host>:3000  (admin / GRAFANA_PASSWORD)
```
