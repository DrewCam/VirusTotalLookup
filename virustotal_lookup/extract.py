import re
import ipaddress
from . import config

md5_pattern = r"\b[a-fA-F0-9]{32}\b"
sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
ipv6_pattern = r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|\b(?:[a-fA-F0-9]{0,4}:){2,7}(?:[a-fA-F0-9]{1,4})\b"
domain_pattern = r"(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"


def is_internal_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def extract_entities():
    entities = {"MD5": [], "SHA1": [], "SHA256": [], "IPv4": [], "IPv6": [], "Domain": []}

    with open(config.input_file_path, "r") as file:
        content = file.read()

    entities["MD5"].extend(re.findall(md5_pattern, content))
    entities["SHA1"].extend(re.findall(sha1_pattern, content))
    entities["SHA256"].extend(re.findall(sha256_pattern, content))

    for ip in re.findall(ipv4_pattern, content):
        if not is_internal_ip(ip):
            entities["IPv4"].append(ip)
    for ip in re.findall(ipv6_pattern, content):
        if not is_internal_ip(ip):
            entities["IPv6"].append(ip)

    for match in re.finditer(domain_pattern, content):
        domain = match.group(0)
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.lstrip("www.")
        entities["Domain"].append(domain)

    with open(config.output_file_path, "w") as output_file:
        for entity_type, entity_list in entities.items():
            output_file.write(f"\n--- {entity_type} ---\n")
            for entity in entity_list:
                output_file.write(f"{entity}\n")

    return entities
