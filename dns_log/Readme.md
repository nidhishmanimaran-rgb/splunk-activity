DNS Log Analysis Using Splunk SIEM

This project demonstrates how DNS (Domain Name System) logs can be analyzed using Splunk SIEM to identify suspicious DNS activity, monitor DNS traffic, and perform threat detection using SPL queries. The project is based on beginner-friendly Splunk SIEM labs and DNS log analysis workflows.

Introduction

DNS logs are an important source of network information and help security analysts detect:

Suspicious domains
Malware communication
Failed DNS responses
Abnormal DNS traffic patterns
Potential Indicators of Compromise (IOCs)

Splunk SIEM provides powerful capabilities to:

Ingest DNS logs
Search events
Extract fields
Visualize data
Detect anomalies using SPL queries
Prerequisites

Before starting the project, ensure the following:

Splunk Enterprise is installed and configured
DNS log file is available
Splunk Search & Reporting App is accessible
Tools Used
Splunk Enterprise
Windows Operating System
DNS Sample Log File
SPL (Search Processing Language)
Log File Details

The DNS log file contains:

Source IP address
Destination IP address
Domain Name (FQDN)
Query Type
Response Code

Example log:

2026-05-06 10:15:01 src_ip=192.168.1.10 dest_ip=8.8.8.8 fqdn=google.com query_type=A response_code=NOERROR
Steps Performed
1. Upload DNS Log File

The DNS log file was uploaded into Splunk using:

Settings → Add Data → Upload

The uploaded file was indexed into:

Index: main

The custom sourcetype used:

dns_sample-too_small
SPL Queries Used
1. View All DNS Events
index=main sourcetype="dns_sample-too_small"

Purpose:

Displays all uploaded DNS log events.
2. Identify Suspicious DNS Responses
index=main sourcetype="dns_sample-too_small" response_code=NXDOMAIN OR response_code=SERVFAIL

Purpose:

Detects suspicious or failed DNS responses.
Helps identify potentially malicious domains.

Findings:

maliciousdomain.com
suspicious-site.xyz
3. Find Top Queried Domains
index=main sourcetype="dns_sample-too_small" | stats count by fqdn

Purpose:

Displays frequently queried domains.
Helps identify abnormal DNS activity.
4. Find Top Source IP Addresses
index=main sourcetype="dns_sample-too_small" | top src_ip

Purpose:

Identifies systems generating DNS traffic.
5. Analyze DNS Query Types
index=main sourcetype="dns_sample-too_small" | stats count by query_type

Purpose:

Displays DNS query type distribution.

Example query types:

A
AAAA
TXT
6. Extract DNS Related Events Using Regex
index=main sourcetype="dns_sample-too_small" | regex _raw="(?i)\b(fqdn|query_type|response_code)\b"

Purpose:

Filters DNS-related fields from raw events.
7. Identify Uploaded DNS Log File
index=* source="*Downloads*dns*"

Purpose:

Finds uploaded DNS log files from the Downloads directory.
Visualization

Visualization was created using:

index=main sourcetype="dns_sample-too_small" | stats count by fqdn

Chart Types:

Area Chart
Bar Chart

Purpose:

Provides graphical representation of DNS traffic patterns.
