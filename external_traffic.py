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