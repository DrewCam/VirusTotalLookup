import time
import requests
from . import config


def query_virustotal(entity: str, entity_type: str):
    headers = {"x-apikey": config.API_KEY}
    if entity_type in ["MD5", "SHA1", "SHA256"]:
        url = f"{config.API_URL_BASE}files/{entity}"
    elif entity_type in ["IPv4", "IPv6"]:
        url = f"{config.API_URL_BASE}ip_addresses/{entity}"
    elif entity_type == "Domain":
        url = f"{config.API_URL_BASE}domains/{entity}"
    else:
        return None

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 204:
            time.sleep(60)
            response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        print(f"Error querying {entity}: {exc}")
        return None


def process_report(entity: str, entity_type: str, report: dict):
    attributes = report["data"]["attributes"]

    if entity_type in ["MD5", "SHA1", "SHA256"]:
        return {
            "Type": attributes.get("type_description", "Unknown"),
            "Detection": "Malicious" if attributes["last_analysis_stats"].get("malicious", 0) > 0 else "Not Malicious",
            "Tags": ", ".join(attributes.get("tags", [])),
            "Signed": "Signed" if attributes.get("signature_info") else "Unsigned",
            "Signer": attributes.get("signature_info", {}).get("product", "Unknown"),
            "Name": attributes.get("meaningful_name", entity),
        }
    elif entity_type in ["IPv4", "IPv6"]:
        return {
            "Reputation": attributes.get("reputation", "No reputation data"),
            "Malicious": "Yes" if attributes["last_analysis_stats"].get("malicious", 0) > 0 else "No",
            "Country": attributes.get("country", "Unknown"),
            "Organization": attributes.get("as_owner", "Unknown"),
            "Categories": ", ".join(attributes.get("categories", [])),
        }
    elif entity_type == "Domain":
        return {
            "Reputation": attributes.get("reputation", "No reputation data"),
            "Malicious": "Yes" if attributes["last_analysis_stats"].get("malicious", 0) > 0 else "No",
            "Registrar": attributes.get("registrar", "Unknown"),
            "Organization": attributes.get("last_https_certificate", {}).get("issuer", {}).get("O", "Unknown"),
            "Categories": ", ".join(attributes.get("categories", [])),
        }
