from datetime import datetime
import os
import time
from . import config
from . import vt_api


def configure_report_file():
    if config.report_file_path.exists() and config.report_file_path.stat().st_size > 0:
        print("Report file already exists.")
        mode = input("Choose action: (A)ppend, (O)verwrite, (N)ew file: ").strip().upper()
        if mode == "A":
            return "a"
        if mode == "O":
            return "w"
        if mode == "N":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            config.report_file_path = config.ROOT_DIR / f"virustotal_report_{timestamp}.txt"
            return "w"
    return "w"


def get_reports(entities: dict):
    request_count = 0
    queried_entities = set()
    redundant_entities = set()
    mode = configure_report_file()

    with open(config.report_file_path, mode) as report_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_file.write(f"\n=== VirusTotal Report - Run Date/Time: {timestamp} ===\n\n")

        for entity_type, entity_list in entities.items():
            for entity in entity_list:
                if request_count >= config.DAILY_LIMIT:
                    print("Reached daily limit. Stopping further requests.")
                    break

                if entity in queried_entities:
                    redundant_entities.add(entity)
                    continue

                report = vt_api.query_virustotal(entity, entity_type)
                request_count += 1
                queried_entities.add(entity)

                if report:
                    summary = vt_api.process_report(entity, entity_type, report)
                    print(f"\n--- Report Summary for {entity} ({entity_type}) ---")
                    for key, value in summary.items():
                        print(f"{key}: {value}")

                    report_file.write(f"\n--- Report Summary for {entity} ({entity_type}) ---\n")
                    for key, value in summary.items():
                        report_file.write(f"{key}: {value}\n")
                    report_file.write("\n" + "-" * 50 + "\n\n")

                for remaining in range(config.RATE_LIMIT_DELAY, 0, -1):
                    print(f"\rNext query in {remaining} seconds...", end="")
                    time.sleep(1)
                print("\rQuerying next entity...       ", end="")
                print()

        print(f"\nTotal entities queried: {len(queried_entities)}")
        print(f"Total redundant entities skipped: {len(redundant_entities)}")
        report_file.write(f"\nTotal entities queried: {len(queried_entities)}\n")
        report_file.write(f"Total redundant entities skipped: {len(redundant_entities)}\n")
