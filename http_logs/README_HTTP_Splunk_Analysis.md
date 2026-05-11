# HTTP Log Analysis Using Splunk SIEM

## Base Search Query

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
```

Purpose:
- Retrieves all HTTP log events from the uploaded log file.

---

# 1. Extract Important HTTP Fields

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "\"(?<method>GET|POST|PUT|DELETE)\s(?<uri>[^\s]+)"
| rex field=_raw "\"\s(?<status>\d{3})\s"
| table _time src_ip method uri status
```

Purpose:
- Extracts:
  - Source IP Address
  - HTTP Method
  - URL/URI
  - HTTP Status Code
- Displays them in a table format.

---

# 2. Count HTTP Request Methods

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| rex field=_raw "\"(?<method>GET|POST|PUT|DELETE)"
| stats count by method
```

Purpose:
- Counts GET, POST, PUT, DELETE requests.
- Helps analyze traffic distribution.

---

# 3. Top Accessed URLs

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| rex field=_raw "\"(?:GET|POST)\s(?<uri>[^\s]+)"
| top limit=10 uri
```

Purpose:
- Shows the most frequently accessed URLs.
- Useful for identifying popular endpoints or suspicious activity.

---

# 4. HTTP Status Code Analysis

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| rex field=_raw "\"\s(?<status>\d{3})\s"
| stats count by status
```

Purpose:
- Counts HTTP response codes.
- Detects:
  - 200 → Success
  - 401 → Unauthorized
  - 403 → Forbidden
  - 404 → Not Found
  - 500 → Server Error

---

# 5. Detect Error Responses

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| rex field=_raw "\"\s(?<status>\d{3})\s"
| where status>=400
| stats count by status
```

Purpose:
- Detects client/server errors.
- Helps identify attacks or server issues.

---

# 6. Traffic Timeline Analysis

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| timechart span=1h count
```

Purpose:
- Visualizes HTTP traffic over time.
- Detects spikes, scanning activity, or DDoS attempts.

---

# 7. Detect Suspicious IP Activity

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort - count
```

Purpose:
- Identifies the most active IP addresses.
- Helps detect suspicious or malicious clients.

---

# 8. Detect Failed Login Attempts

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "\"POST\s(?<uri>[^\s]+)"
| rex field=_raw "\"\s(?<status>\d{3})\s"
| search uri="/login" status=401
| stats count by src_ip
```

Purpose:
- Detects brute-force login attempts.
- Monitors repeated failed authentications.

---

# 9. Show Raw Logs

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| table _time _raw
```

Purpose:
- Displays complete raw log entries.
- Useful for manual investigation.

---

# 10. Complete HTTP Analysis Query

```spl
source="F:\\http_logs.log" host="DESKTOP-ASR80SO" index="main" sourcetype="http_logs"
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "\"(?<method>GET|POST|PUT|DELETE)\s(?<uri>[^\s]+)"
| rex field=_raw "\"\s(?<status>\d{3})\s"
| stats count by src_ip method uri status
| sort - count
```

Purpose:
- Provides complete HTTP traffic analysis.
- Combines:
  - IP Address
  - Method
  - URL
  - Status Code
  - Request Counts

---

# Learning Outcomes

After completing this project, you will understand:

- HTTP log ingestion in Splunk
- SPL query writing
- Field extraction using rex
- Web traffic analysis
- Security monitoring
- Detecting suspicious activity
- Basic SIEM operations

---

# Real Security Use Cases

| Threat Type | Detection Method |
|-------------|-----------------|
| Brute Force Attack | Multiple 401 responses |
| Web Scanning | Many URLs from one IP |
| DDoS Attack | Sudden traffic spike |
| Unauthorized Access | 403 responses |
| Server Errors | 500 responses |

