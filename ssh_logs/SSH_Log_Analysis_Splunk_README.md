# Analyzing SSH Log Files Using Splunk SIEM

## Introduction
SSH (Secure Shell) log files contain valuable information about remote access to servers, including login attempts, commands executed, and session details. Analyzing SSH logs using Splunk SIEM enables security professionals to monitor access to critical systems, detect anomalies, and identify potential security threats.

---

# Project Overview
In this project, we will:

- Upload sample SSH log files into Splunk SIEM
- Extract important SSH fields
- Analyze login activity
- Detect suspicious SSH behavior
- Identify brute-force attacks
- Monitor user activity

---

# Prerequisites
Before starting the project, ensure the following:

- Splunk Enterprise is installed and configured
- SSH log sources are available
- Splunk Search & Reporting app is accessible
- Sample SSH log file is ready

---

# Sample SSH Log Example

```log
May 11 10:15:22 server1 sshd[1024]: Accepted password for admin from 192.168.1.10 port 55221 ssh2
May 11 10:16:01 server1 sshd[1025]: Failed password for root from 192.168.1.20 port 55310 ssh2
May 11 10:17:44 server1 sshd[1026]: Accepted password for user1 from 192.168.1.15 port 55345 ssh2
May 11 10:18:11 server1 sshd[1027]: Failed password for invalid user test from 192.168.1.30 port 55400 ssh2
```

---

# Verify Uploaded Logs

```spl
index="main" sourcetype="ssh_logs"
```

---

# Extract Username

```spl
index="main" sourcetype="ssh_logs"
| rex field=_raw "for\s+(?<user>\w+)"
| table _time user
```

---

# Extract Source IP Address

```spl
index="main" sourcetype="ssh_logs"
| rex field=_raw "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time src_ip
```

---

# Identify Top Users and Source IP Addresses

```spl
index="main" sourcetype="ssh_logs"
| rex field=_raw "for\s+(?<user>\w+)"
| rex field=_raw "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| top limit=10 user src_ip
```

---

# Analyze Successful vs Failed SSH Logins

```spl
index="main" sourcetype="ssh_logs"
| eval action=if(searchmatch("Accepted"),"success","failed")
| stats count by action
```

---

# Detect Login Spikes Over Time

```spl
index=* sourcetype="ssh_logs"
| timechart span=1h count
```

---

# Investigate Suspicious Source IP Addresses

```spl
index="main" sourcetype="ssh_logs"
| rex field=_raw "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| search src_ip="192.168.1.20"
```

---

# Detect Brute Force Attacks

```spl
index="main" sourcetype="ssh_logs"
| search "Failed password"
| rex field=_raw "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
| sort - count
```

---

# Identify Users with Multiple Failed Logins

```spl
index="main" sourcetype="ssh_logs"
| rex field=_raw "for\s+(?<user>\w+)"
| eval action=if(searchmatch("Accepted"),"success","failed")
| search action="failed"
| stats count by user
```

---

# Analyze User Session Duration

```spl
index="main" sourcetype="ssh_logs"
| rex field=_raw "for\s+(?<user>\w+)"
| stats range(_time) as session_duration by user
| stats avg(session_duration) as avg_session_duration by user
```

---

# Useful Splunk Commands

| Command | Purpose |
|---|---|
| search | Filter events |
| rex | Extract fields |
| stats | Generate statistics |
| top | Show top values |
| table | Display fields |
| timechart | Time-based analysis |
| eval | Create calculated fields |
| where | Filter conditions |

---

# Conclusion

Analyzing SSH log files using Splunk SIEM helps organizations monitor SSH activity, detect suspicious login attempts, identify brute-force attacks, and improve overall security monitoring.
