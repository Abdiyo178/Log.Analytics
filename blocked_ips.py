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



