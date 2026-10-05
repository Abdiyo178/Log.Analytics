import csv

# Scanner tool names to look for in the user_agent field
scanner_tools = ["nmap", "nikto", "sqlmap"]

# Empty dict: key = source IP, value = set of tools that IP used
scanners = {}

with open("cybersecurity_threat_detection_logs.csv") as file:
    # Create a DictReader from the file
    reader = csv.DictReader(file)
    # Loop through each row
    for row in reader:
        # Check every tool name against this row's user agent
        for tool in scanner_tools:
            # Is this tool's name inside the user agent? (lowercase both so capitalization doesn't matter)
            if tool in row["user_agent"].lower():
                # Seen this IP before? Add the tool to its existing set
                if row["source_ip"] in scanners:
                    scanners[row["source_ip"]].add(tool)
                # First time seeing this IP: create its set with this tool
                else:
                    scanners[row["source_ip"]] = {tool}

# Report each flagged IP and the tools it used
for source_ip, tools in scanners.items():
    print(source_ip, tools)