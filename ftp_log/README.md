FTP Log Analysis Using Splunk SIEM
Introduction

FTP (File Transfer Protocol) log files contain valuable information about file transfer activities within a network. Analyzing FTP logs using Splunk SIEM helps security analysts monitor file transfers, detect anomalies, identify suspicious activity, and investigate potential security threats.

This project demonstrates how FTP log files can be uploaded into Splunk and analyzed using SPL (Search Processing Language) queries.

Project Overview

In this project:

Sample FTP log files were uploaded into Splunk SIEM
FTP events were analyzed using SPL queries
File transfer activities were monitored
Suspicious login attempts and anomalies were identified
Visualizations were created for better monitoring and analysis
Prerequisites

Before starting the project, the following requirements were completed:

Splunk Enterprise installed and configured
FTP sample log file prepared
Splunk Search & Reporting app accessible
FTP logs uploaded into Splunk index
Tools Used
Splunk Enterprise
Windows Operating System
FTP Sample Log File
SPL (Search Processing Language)
FTP Log File Details

The FTP log file contains:

Timestamp
Source IP address
Username
FTP commands
File names
File paths
Login status

Example FTP log:

2026-05-06 11:20:15 192.168.1.10 user1 PUT /files/report.pdf SUCCESS
Uploading FTP Logs into Splunk

The FTP log file was uploaded using:

Settings → Add Data → Upload

Configuration used:

Index: main
Sourcetype: ftp
Host: Local system

After upload, events were verified using Splunk Search & Reporting.

SPL Queries Used
1. View All FTP Events
index=main sourcetype=ftp

Purpose:

Displays all FTP log events uploaded into Splunk.
2. Extract FTP Fields Using Regex
index=main sourcetype=ftp 
| rex field=_raw "^(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(?<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(?<username>\w+).*?(?<command>[A-Z]+).*?(?<file_path>\/[\w\/.-]+)"

Purpose:

Extracts important FTP fields:
Timestamp
Source IP
Username
FTP command
File path
File Transfer Activity Analysis
3. Analyze File Transfer Frequency
index=main sourcetype=ftp | stats count by username

Purpose:

Displays number of file transfers by user.
4. Identify Top Source IP Addresses
index=main sourcetype=ftp | top source_ip

Purpose:

Identifies systems generating the most FTP activity.
5. Analyze FTP Commands
index=main sourcetype=ftp | stats count by command

Purpose:

Displays commonly used FTP commands such as:
GET
PUT
DELETE
6. Analyze File Types
index=main sourcetype=ftp | stats count by file_path

Purpose:

Identifies transferred files and file activity.
Detecting Anomalies
7. Detect Failed Login Attempts
index=main sourcetype=ftp "FAILED LOGIN"

Purpose:

Detects failed or unauthorized login attempts.
8. Detect Suspicious IP Addresses
index=main sourcetype=ftp | stats count by source_ip

Purpose:

Helps identify suspicious or abnormal FTP activity.
9. Monitor Sudden Spikes in FTP Activity
index=main sourcetype=ftp | timechart count

Purpose:

Visualizes FTP traffic trends over time.
Detects unusual spikes or drops in activity.
Visualization

Visualization was created using:

index=main sourcetype=ftp | stats count by username

Chart Types Used:

Bar Chart
Pie Chart
Line Chart

Purpose:

Provides graphical representation of FTP activity and user behavior.
Findings
FTP file transfer activities were successfully monitored.
User activity and source IP behavior were analyzed.
Failed login attempts were detected.
Suspicious transfer patterns were identified.
Splunk visualizations improved monitoring and analysis efficiency.
Conclusion

This project demonstrated how Splunk SIEM can be used to:

Upload and ingest FTP logs
Analyze FTP traffic
Monitor user behavior
Detect suspicious login attempts
Identify anomalies in file transfer activity
Visualize FTP events using SPL queries

The project provided practical experience in SIEM operations, log analysis, and security monitoring using Splunk Enterprise.
