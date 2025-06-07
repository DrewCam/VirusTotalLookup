import os
import sys
import requests
import time
from datetime import datetime
from dotenv import load_dotenv
import re
import ipaddress

# Load environment variables from .env file
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    print("Error: VirusTotal API key is missing. Please set VT_API_KEY in your environment or .env file.")
    sys.exit(1)
API_URL_BASE = "https://www.virustotal.com/api/v3/"

# Set rate limits
RATE_LIMIT_DELAY = 15  # 4 requests per minute
DAILY_LIMIT = 500  # VirusTotal public API daily limit

# Define paths
script_dir = os.path.dirname(os.path.abspath(__file__))
input_file_path = os.path.join(script_dir, 'raw.txt')
output_file_path = os.path.join(script_dir, 'out.txt')
report_file_path = os.path.join(script_dir, 'virustotal_report.txt')

# Regex patterns for MD5, SHA1, SHA256, IPs, and domains
md5_pattern = r'\b[a-fA-F0-9]{32}\b'
sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|\b(?:[a-fA-F0-9]{0,4}:){2,7}(?:[a-fA-F0-9]{1,4})\b'
domain_pattern = r'^(?:https?://|www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'

# Extract hashes, IPs, and domains from raw.txt
def extract_entities():
    entities = {
        "MD5": [], "SHA1": [], "SHA256": [], "IPv4": [], "IPv6": [], "Domain": []
    }
    
    with open(input_file_path, 'r') as file:
        content = file.read()

    # Extract hashes
    entities["MD5"].extend(re.findall(md5_pattern, content))
    entities["SHA1"].extend(re.findall(sha1_pattern, content))
    entities["SHA256"].extend(re.findall(sha256_pattern, content))
    
    # Extract and filter IPs, skipping internal/reserved IPs
    for ip in re.findall(ipv4_pattern, content):
        if not is_internal_ip(ip):
            entities["IPv4"].append(ip)
    for ip in re.findall(ipv6_pattern, content):
        if not is_internal_ip(ip):
            entities["IPv6"].append(ip)
    
    # Extract domains
    entities["Domain"].extend(re.findall(domain_pattern, content))
    
    # Write extracted entities to output file
    with open(output_file_path, 'w') as output_file:
        for entity_type, entity_list in entities.items():
            output_file.write(f"\n--- {entity_type} ---\n")
            for entity in entity_list:
                output_file.write(f"{entity}\n")
                
    return entities

# Check if IP is an internal or reserved IP address
def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False  # Invalid IP format

# Configure report file handling mode based on user preference
def configure_report_file():
    global report_file_path
    if os.path.exists(report_file_path) and os.path.getsize(report_file_path) > 0:
        print("Report file already exists.")
        mode = input("Choose action: (A)ppend, (O)verwrite, (N)ew file: ").strip().upper()
        if mode == "A":
            return "a"
        elif mode == "O":
            return "w"
        elif mode == "N":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file_path = os.path.join(script_dir, f"virustotal_report_{timestamp}.txt")
            return "w"
    return "w"

# Query VirusTotal API
def query_virustotal(entity, entity_type):
    headers = {"x-apikey": API_KEY}
    if entity_type in ["MD5", "SHA1", "SHA256"]:
        url = f"{API_URL_BASE}files/{entity}"
    elif entity_type == "IPv4" or entity_type == "IPv6":
        url = f"{API_URL_BASE}ip_addresses/{entity}"
    elif entity_type == "Domain":
        url = f"{API_URL_BASE}domains/{entity}"
    else:
        return None

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 204:
            print("Rate limit reached. Pausing for a minute.")
            time.sleep(60)
            response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error querying {entity}: {e}")
        return None

# Process and summarize VirusTotal report for different entity types
def process_report(entity, entity_type, report):
    attributes = report['data']['attributes']
    
    if entity_type in ["MD5", "SHA1", "SHA256"]:
        return {
            "Type": attributes.get('type_description', 'Unknown'),
            "Detection": "Malicious" if attributes['last_analysis_stats'].get('malicious', 0) > 0 else "Not Malicious",
            "Tags": ', '.join(attributes.get('tags', [])),
            "Signed": "Signed" if attributes.get('signature_info') else "Unsigned",
            "Signer": attributes.get('signature_info', {}).get('product', 'Unknown'),
            "Name": attributes.get('meaningful_name', entity)
        }
    
    elif entity_type == "IPv4" or entity_type == "IPv6":
        return {
            "Reputation": attributes.get('reputation', 'No reputation data'),
            "Malicious": "Yes" if attributes['last_analysis_stats'].get('malicious', 0) > 0 else "No",
            "Country": attributes.get('country', 'Unknown'),
            "Organization": attributes.get('as_owner', 'Unknown'),
            "Categories": ', '.join(attributes.get('categories', []))
        }
    
    elif entity_type == "Domain":
        return {
            "Reputation": attributes.get('reputation', 'No reputation data'),
            "Malicious": "Yes" if attributes['last_analysis_stats'].get('malicious', 0) > 0 else "No",
            "Registrar": attributes.get('registrar', 'Unknown'),
            "Organization": attributes.get('last_https_certificate', {}).get('issuer', {}).get('O', 'Unknown'),
            "Categories": ', '.join(attributes.get('categories', []))
        }

# Generate and save VirusTotal reports
def get_reports(entities):
    request_count = 0
    queried_entities = set()
    redundant_entities = set()
    mode = configure_report_file()

    with open(report_file_path, mode) as report_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_file.write(f"\n=== VirusTotal Report - Run Date/Time: {timestamp} ===\n\n")

        for entity_type, entity_list in entities.items():
            for entity in entity_list:
                if request_count >= DAILY_LIMIT:
                    print("Reached daily limit. Stopping further requests.")
                    break
                
                if entity in queried_entities:
                    redundant_entities.add(entity)
                    continue
                
                report = query_virustotal(entity, entity_type)
                request_count += 1
                queried_entities.add(entity)
                
                if report:
                    summary = process_report(entity, entity_type, report)
                    print(f"\n--- Report Summary for {entity} ({entity_type}) ---")
                    for key, value in summary.items():
                        print(f"{key}: {value}")

                    report_file.write(f"\n--- Report Summary for {entity} ({entity_type}) ---\n")
                    for key, value in summary.items():
                        report_file.write(f"{key}: {value}\n")
                    report_file.write("\n" + "-" * 50 + "\n\n")

                for remaining in range(RATE_LIMIT_DELAY, 0, -1):
                    print(f"\rNext query in {remaining} seconds...", end="")
                    time.sleep(1)
                print("\rQuerying next entity...       ", end="")  # Clear remaining countdown text
                print()  # Move to a new line

        # Summary at the end of report generation
        print(f"\nTotal entities queried: {len(queried_entities)}")
        print(f"Total redundant entities skipped: {len(redundant_entities)}")
        report_file.write(f"\nTotal entities queried: {len(queried_entities)}\n")
        report_file.write(f"Total redundant entities skipped: {len(redundant_entities)}\n")

# Main process
def main():
    # Extract entities (hashes, IPs, domains) from input file
    entities = extract_entities()

    # Display available entity types and counts
    print("\nAvailable entity types for querying:")
    entity_options = []
    for entity_type, entity_list in entities.items():
        count = len(entity_list)
        if count > 0:
            print(f"{len(entity_options) + 1}. {entity_type}: {count} found")
            entity_options.append(entity_type)
        else:
            print(f"{len(entity_options) + 1}. {entity_type}: None found")
            entity_options.append(entity_type)

    # Add "All" and "Exit" options
    print(f"{len(entity_options) + 1}. All")
    print(f"{len(entity_options) + 2}. Exit")

    # Get user input for types to query
    while True:
        try:
            user_input = input("\nEnter the numbers of the types you want to query (comma-separated): ")
            if user_input.strip() == str(len(entity_options) + 2):  # Exit option
                print(f"Exiting. Cleaned entity list available at {output_file_path}.")
                return
            
            if user_input.strip() == str(len(entity_options) + 1):  # All option
                selected_entities = {etype: entities[etype] for etype in entity_options if entities[etype]}
                break
            
            selected_indices = {int(x.strip()) - 1 for x in user_input.split(",")}
            selected_entities = {entity_options[i]: entities[entity_options[i]] for i in selected_indices if i < len(entity_options) and entities[entity_options[i]]}
            
            if selected_entities:
                break
            else:
                print("No valid types selected. Please try again.")
        except (ValueError, IndexError):
            print("Invalid input. Please enter numbers corresponding to entity types.")

    # Generate report for selected entities
    if selected_entities:
        print("Starting VirusTotal queries...")
        get_reports(selected_entities)
        print(f"Report saved to {report_file_path}")
    else:
        print("No entities available for querying.")

# Execute the main function if this script is run directly
if __name__ == "__main__":
    main()
