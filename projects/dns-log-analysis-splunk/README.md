# DNS Log Analysis with Splunk SIEM

## Project Overview

This project demonstrates a practical DNS log analysis workflow using Splunk Enterprise and a simulated CSV dataset. The objective was to search DNS events, summarize response codes, identify frequently queried domains, and review DNS activity by client IP address.

- **Environment:** Splunk Enterprise
- **Data source:** `sample_dns_logs.csv`
- **Dataset type:** Simulated practice data
- **Events analysed:** 15 DNS records

## Objectives

- Import a CSV file containing sample DNS records into Splunk.
- Search and filter DNS events using Search Processing Language (SPL).
- Count DNS responses by response code.
- Identify frequently queried domains.
- Examine DNS requests by client IP and domain.
- Interpret findings carefully without treating individual response codes as proof of an attack.

## Dataset Fields

- `src_ip` — client IP address that made the DNS request.
- `query_domain` — domain name requested.
- `query_type` — DNS record type requested, such as `A`.
- `response_code` — DNS response status.
- `answers` — number of answers returned.
- `_time` — event timestamp assigned or extracted by Splunk.

The records are simulated and are not evidence of activity on a real network.

## Analysis and SPL Queries

### 1. Count DNS events by response code

```spl
source="sample_dns_logs.csv"
| stats count by response_code
| sort - count
```

**Purpose:** Count events for each DNS response code and sort the results from highest to lowest.

**Observed results:**

| Response code | Events | Share |
|---|---:|---:|
| `NOERROR` | 9 | 60% |
| `NXDOMAIN` | 3 | 20% |
| `REFUSED` | 3 | 20% |
| **Total** | **15** | **100%** |

**Interpretation:** Most records returned `NOERROR`. Three records returned `NXDOMAIN`, meaning the requested names did not exist, and three returned `REFUSED`, meaning the DNS server refused those requests. These responses need context and do not, by themselves, prove malicious activity.

### 2. Identify frequently queried domains

```spl
source="sample_dns_logs.csv"
| stats count by query_domain
| sort - count
```

**Purpose:** Count how often each domain appears in the dataset.

**Observed results:**

| Domain | Queries |
|---|---:|
| `demo-blocked.example` | 3 |
| `example.com` | 3 |
| `nonexistent-demo.invalid` | 3 |
| `docs.python.org` | 1 |
| `example.net` | 1 |
| `github.com` | 1 |
| `iana.org` | 1 |
| `openai.com` | 1 |
| `wikipedia.org` | 1 |
| **Total** | **15** |

**Interpretation:** Three domains appeared three times each. Repeated queries can be caused by normal application behaviour, retries, or configuration issues; further investigation is needed before drawing a security conclusion.

### 3. Group DNS activity by client and domain

```spl
source="sample_dns_logs.csv"
| stats count values(response_code) as response_codes by src_ip query_domain
| sort - count
```

**Purpose:** See which client IP addresses queried each domain and how many times, along with the response codes.

**Observed examples:**

- `192.168.1.12` queried `nonexistent-demo.invalid` three times and received `NXDOMAIN`.
- `192.168.1.15` queried `demo-blocked.example` twice and received `REFUSED`.
- `192.168.1.18` queried `demo-blocked.example` once and received `REFUSED`.
- `192.168.1.10` queried `example.com` twice and received `NOERROR`.

### 4. Inspect one client's DNS events

```spl
source="sample_dns_logs.csv" src_ip="192.168.1.12"
| table _time src_ip query_domain query_type response_code answers
| sort _time
```

**Purpose:** Review timestamps, domain, query type, response code, and answer count for a selected client.

**Observed result:** Three queries from `192.168.1.12` requested `nonexistent-demo.invalid`. All three returned `NXDOMAIN` with zero answers.

**Assessment:** Possible explanations include a mistyped domain, an application using an incorrect hostname, or repeated DNS retries. The sample alone does not establish the cause.

### 5. Count unsuccessful domain lookups by client

```spl
source="sample_dns_logs.csv" response_code="NXDOMAIN"
| stats count by src_ip
| sort - count
```

**Observed result:** `192.168.1.12` had three `NXDOMAIN` events in this dataset.

### 6. Review refused DNS requests

```spl
source="sample_dns_logs.csv" response_code="REFUSED"
| stats count by src_ip query_domain
| sort - count
```

**Observed results:**

- `192.168.1.15` — two refused requests for `demo-blocked.example`.
- `192.168.1.18` — one refused request for `demo-blocked.example`.

### 7. Summarize response codes by client

```spl
source="sample_dns_logs.csv"
| stats count by response_code src_ip
| sort response_code - count
```

**Observed summary:**

- Nine `NOERROR` events were associated with six client IP addresses.
- Three `NXDOMAIN` events were associated with `192.168.1.12`.
- Three `REFUSED` events were associated with `192.168.1.15` and `192.168.1.18`.

## Key Findings

1. The dataset contained 15 DNS events across nine queried domains.
2. `NOERROR` was the most common response, with nine events.
3. `NXDOMAIN` appeared three times, all from `192.168.1.12` querying `nonexistent-demo.invalid`.
4. `REFUSED` appeared three times for `demo-blocked.example`, across clients `192.168.1.15` and `192.168.1.18`.
5. The repeated requests were useful investigation leads, but the simulated data did not establish that an attack occurred.

## Conclusion

This lab provided practice in importing CSV data into Splunk Enterprise, writing SPL searches, grouping and counting DNS events, identifying repeated domain queries, and examining activity by client IP. It also reinforced the importance of validating context before classifying activity as malicious.

## Limitations and Next Steps

- The dataset is simulated and contains only 15 records.
- Findings cannot be generalized to a real network.
- Further practice could correlate DNS events with firewall, endpoint, authentication, and network logs.
- Any real-world assessment would require more context, baseline behaviour, and corroborating evidence.
## Screenshots
<img width="975" height="180" alt="image" src="https://github.com/user-attachments/assets/69399406-cbd4-4d86-8f40-0885b00f3f24" />



<img width="975" height="333" alt="image" src="https://github.com/user-attachments/assets/05c28eef-e9d5-476e-832f-253cc30104b4" />



<img width="975" height="396" alt="image" src="https://github.com/user-attachments/assets/7f8cb2ec-2692-44cc-acfe-05ad81ce9a82" />



<img width="975" height="434" alt="image" src="https://github.com/user-attachments/assets/6a7bf963-519e-4358-a6e3-225b371cf2cd" />



<img width="975" height="260" alt="image" src="https://github.com/user-attachments/assets/9ea44d1f-1d97-4c0f-a471-f138635fe052" />



<img width="975" height="218" alt="image" src="https://github.com/user-attachments/assets/015b3f2a-181c-4217-a3e7-171b3e47a787" />


<img width="975" height="241" alt="image" src="https://github.com/user-attachments/assets/573b9f79-8417-4875-a772-74ccef2fc95f" />


## Skills Practised

- Splunk Enterprise search
- Search Processing Language (SPL)
- CSV log ingestion and review
- DNS response-code interpretation
- Event aggregation with `stats`
- Result ordering with `sort`
- Filtering and inspecting events with `table`
- Basic security triage and evidence-based reporting
