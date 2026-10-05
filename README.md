# Log.Analytics — Python Fundamentals Projects

Oct 3, 2026 · @Abdifatah Adan

## Objective

Build three small Python scripts that answer basic triage questions from cybersecurity threat detection logs, written by hand to practice core Python on realistic security data.

The focus is fundamentals: variables, data structures, conditionals, and loops, applied to the kind of question an analyst asks every day. Projects 1–3 are written by hand. The fundamentals from these three are what I use to review and validate the automations and detections a coding agent writes.

## Data source and setup

| Item | Detail |
| --- | --- |
| Dataset | [Cybersecurity Threat Detection Logs (Kaggle)](https://www.kaggle.com/datasets/aryan208/cybersecurity-threat-detection-logs) |
| Local file | `cybersecurity_threat_detection_logs.csv` |
| Columns | timestamp, source\_ip, dest\_ip, protocol, action, threat\_label, log\_type, bytes\_transferred, user\_agent, request\_path |
| Language | Python 3, standard library only (`csv` module) |
| Folder | `Log.Analytics/`, with each script next to the CSV |
| Run | `python3 blocked_ips.py` from inside `Log.Analytics` |

The full CSV stays out of the GitHub repo. The repo links to Kaggle and includes a small sample file so anyone can run the scripts.

## Project list

Three hand-written projects use the Kaggle data. Each reuses the same loop and tests a field a different way.

| # | Script | Question it answers | Check it practices | Built |
| --- | --- | --- | --- | --- |
| 1 | `blocked_ips.py` | Which source IPs had traffic blocked? | Equality: `==` | By hand, done |
| 2 | `scanner_detector.py` | Which source IPs look like scanners, and which tools did they use? | Dict of sets; contains: `in` | Done: fan-out by hand, tool check with AI help |
| 3 | `external_traffic.py` | Which way is traffic flowing, and what outside traffic got in? | Private check: `ipaddress` `.is_private`; `and` / `not` | Done: code written with AI help |

## Project 1: blocked\_ips.py

The script works: it reads every event in the log and prints each unique source IP whose traffic was blocked.

**Question:** Which source IPs were blocked?

**Approach.** I wrote the plan as comments first, then filled in the code under each one:

1. Import the `csv` module.
2. Create an empty set to hold blocked IPs, since a set keeps each IP only once.
3. Open the log file.
4. Create a `DictReader`, which turns each row into a dictionary keyed by column name.
5. Loop through each row.
6. Check whether the row's `action` is `"blocked"`.
7. If it is, add the row's `source_ip` to the set.
8. After the loop, print the set.

**Code**

```python
# Import the csv module
import csv
# Create an empty set for blocked IPS
blocked_ips = set()
# Open the log file
with open("cybersecurity_threat_detection_logs.csv") as file:
    # Create a DictReader from the file
    reader = csv.DictReader(file)
    # Loop through each row
    for row in reader:
        # Check if action is "blocked"
        if row["action"] == "blocked":
            # If yes, add the source_ip to your set
            blocked_ips.add(row["source_ip"])
# Print the Results
print(blocked_ips)
```

**Output.** One set of unique IPs, printed once. A large share start with `192.168.1.`, which means internal machines are getting blocked, not only outside traffic. Project 3 will separate the two.

**What I learned**

- **Plan in comments first.** The comment "create an *empty* set" already told me the answer: `set()` with nothing inside.
- **Column names are not variables.** `action` and `source_ip` only exist as keys inside `row`, so I read them with `row["action"]` and `row["source_ip"]`.
- **`reader` vs `row`.** `reader` is the whole file; `row` is the one entry the loop is on. Checks and reads always start from `row`.
- **Save what you create.** `csv.DictReader(file)` on its own line is thrown away; `reader = ...` keeps it.
- **Sets use `.add()`, lists use `.append()`.** Sets have no order, so there is no end to append to.
- **Methods vs functions.** Methods attach with a dot (`blocked_ips.add(...)`); built-in functions wrap around (`print(...)`, `len(...)`).
- **Indentation decides how often a line runs.** My first version had `print` inside the loop and printed the whole set once per row. At zero indentation it runs once.
- **Test small first.** `print(row)` plus `break` confirms the file reads correctly before writing real logic. Ctrl+C stops a runaway script.

## Project 2: scanner\_detector.py

Fan-out found no signal in this dataset: every source IP touched all 254 possible destinations. The detection pivoted to scanner names in `user_agent`.

**Question:** Which source IPs look like scanners, and which tools did they use?

**Approach.** I planned in comments first, then filled in the code. The first version tested fan-out, one source IP touching many different destinations:

1. Import the `csv` module.
2. Create an empty dict: key = source IP, value = a set of destinations it touched.
3. Open the log file and create a `DictReader`.
4. Loop through each row.
5. Check whether the row's `source_ip` is already a key in the dict.
6. If it is, add the row's `dest_ip` to that IP's set.
7. If not, create the key with a new set holding this first destination.
8. After the loop, use a second loop with `.items()` to print each IP and `len()` of its set.

**Code: fan-out check**

```python
import csv

fanout = {}

with open("cybersecurity_threat_detection_logs.csv") as file:
    # Create a DictReader from the file
    reader = csv.DictReader(file)
    # Loop through each row
    for row in reader:
        # Check: is this row's source IP already in the dict?
        if row["source_ip"] in fanout:
            # If yes, add the dest_ip to that IP's set
            fanout[row["source_ip"]].add(row["dest_ip"])
        else:
            # First time seeing this IP: create its set
            fanout[row["source_ip"]] = {row["dest_ip"]}

# Report each source IP and how many unique destinations it hit
for source_ip, destinations in fanout.items():
    print(source_ip, len(destinations))
```

**Output.** Every source IP printed 254, the number of usable addresses in `192.168.1.x`. Each IP had reached every possible destination, so the signal is saturated and no threshold can separate a scanner from normal traffic. The dataset is synthetic, which likely explains the even spread; the same logic would work on real network logs.

**Pivot: tool fingerprint.** A check of the `user_agent` column showed scanner tool names, so the detection moved there. Same dict-of-sets shape, with an inner loop over a list of tool names and the tool name stored in each IP's set:

```python
import csv

# Scanner tool names to look for in the user_agent field
scanner_tools = ["nmap", "nikto", "sqlmap"]

# Key = source IP, value = set of tools that IP used
scanners = {}

with open("cybersecurity_threat_detection_logs.csv") as file:
    reader = csv.DictReader(file)
    for row in reader:
        # Check every tool name against this row's user agent
        for tool in scanner_tools:
            # Lowercase the user agent so capitalization doesn't matter
            if tool in row["user_agent"].lower():
                if row["source_ip"] in scanners:
                    scanners[row["source_ip"]].add(tool)
                else:
                    scanners[row["source_ip"]] = {tool}

# Report each flagged IP and the tools it used
for source_ip, tools in scanners.items():
    print(source_ip, tools)
```

Open question: tool-check output not yet recorded.

**What I learned**

- **Profile the data before building a detection.** Fan-out was a sound idea, but every IP scored the maximum. A signal everyone maxes out cannot tell normal from malicious.
- **A dict is labeled drawers.** Each key holds its own value, and a value can be a set. `fanout[ip]` opens one drawer; `.add()` fills that set. The dict itself has no `.add()`.
- **`in` does two jobs.** In a `for` it goes through each item; in an `if` it asks whether something is inside. On a dict it checks keys only.
- **Brackets and braces.** Square brackets after a name look a value up (`row["dest_ip"]`); on their own they make a list. Curly braces with a colon make a dict, without one a set, and empty `{}` is a dict.
- **A key is created by assigning to it.** First-time and seen-before IPs need an if/else; adding to a key that doesn't exist raises `KeyError`.
- **The column name is not the value.** `"dest_ip"` is just text; `row["dest_ip"]` is the IP in this row. A whole `row` can't be a dict key.
- **Build in one loop, report in another.** The dict isn't complete until every row is read, so the report loop goes after the first one finishes.
- **Name variables for what they hold.** `destinations` (plural) signals a collection; variable names can't contain spaces.

## Project 3: external\_traffic.py

**Question:** Which traffic crossed the network edge, in which direction, and what outside traffic got in?

**Approach.** The first plan was to flag any `source_ip` that doesn't start with `192.168.`. Looking at the data changed it: direction needs both `source_ip` and `dest_ip`, and most rows are internal-to-internal. So the script labels every row by direction, counts each, and keeps details on inbound traffic that was allowed.

1. Import the `csv` and `ipaddress` modules.
2. Create a dict of direction counts and an empty dict for allowed inbound hits per external IP.
3. Open the log file and create a `DictReader`.
4. For each row, check whether `source_ip` and `dest_ip` are private with `ipaddress.ip_address(...).is_private`.
5. Label the row inbound, outbound, internal or external with `if`/`elif`/`else`.
6. Add 1 to that direction's count.
7. If the row is inbound and `action` is `allowed`, add 1 to that source IP's count, creating the key on first sight.
8. After the loop, print the direction counts, the number of external IPs allowed in, and the top 10 by hits using `sorted()`.

**Code**

```python
import csv
import ipaddress

# Set up storage
direction_counts = {"inbound": 0, "outbound": 0, "internal": 0, "external": 0}
allowed_inbound = {}

# Open the CSV and loop through each row
with open("cybersecurity_threat_detection_logs.csv", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        # Check whether each side of the connection is private (internal)
        src_internal = ipaddress.ip_address(row["source_ip"]).is_private
        dst_internal = ipaddress.ip_address(row["dest_ip"]).is_private

        # Label the direction of the traffic
        if not src_internal and dst_internal:
            direction = "inbound"
        elif src_internal and not dst_internal:
            direction = "outbound"
        elif src_internal and dst_internal:
            direction = "internal"
        else:
            direction = "external"

        # Count it
        direction_counts[direction] += 1

        # Count allowed inbound hits per external IP
        if direction == "inbound" and row["action"] == "allowed":
            ip = row["source_ip"]
            if ip in allowed_inbound:
                allowed_inbound[ip] += 1
            else:
                allowed_inbound[ip] = 1

# Print the summary
print("Traffic by direction:")
for direction, count in direction_counts.items():
    print(f"  {direction}: {count}")

print(f"\nExternal IPs allowed in: {len(allowed_inbound)}")
print("\nTop 10 by allowed inbound hits:")
ranked = sorted(allowed_inbound.items(), key=lambda pair: pair[1], reverse=True)
for ip, hits in ranked[:10]:
    print(f"  {ip}: {hits}")
```

**Output.** The first version printed every allowed inbound connection, too many lines to read. That list still showed SQLMap and Nmap user agents getting in, payloads like `..\..\etc\passwd`, `UNION SELECT` and `DROP TABLE` in request paths, and repeat sources such as 141.26.13.167, 109.9.8.24, 207.12.187.118 and 221.28.64.50 hitting many hosts. The script now ranks external IPs by allowed hits instead; the counts from that run are not in yet.

**What I learned**

- **Direction takes both columns.** External source to internal dest is inbound; internal to external is outbound; internal to internal is lateral.
- **Blocked inbound means defenses worked; allowed inbound is what to review.** An outside IP allowed into `192.168.1.153` is the row an analyst checks first.
- **Use the standard library for IP checks.** `ipaddress` knows every private range, including 172.16–172.31, which `.startswith()` handles badly.
- **Don't trust `threat_label` alone.** That allowed inbound row is still labeled `benign`; `action` plus direction is the stronger signal.
- **Rank, don't list.** Hundreds of raw rows are unreadable; a count per IP sorted with `sorted(..., key=lambda pair: pair[1], reverse=True)` shows who to look at first.
- **Not private doesn't mean real.** Sources in 224–239 (229.x, 236.x, 238.x) are multicast addresses, which shouldn't arrive from the internet. They point to randomly generated data.

## GitHub and outcomes

**GitHub:** repo not created yet. This doc becomes its README.

| Project | What the script found | What clicked |
| --- | --- | --- |
| 1. blocked\_ips.py | Unique blocked source IPs; many are internal `192.168.1.x` hosts | Indentation controls how often a line runs; `reader` vs `row` |
| 2. scanner\_detector.py | Fan-out saturated: every source IP hit all 254 destinations, so no signal; user\_agent does show scanner tools | Dict of sets: the key picks the set, .add() fills it; profile data before designing a detection |
| 3. external\_traffic.py | Allowed inbound includes SQLMap/Nmap traffic and injection or traversal payloads; ranked counts pending | Direction needs both source and dest; allowed inbound is what to review |
