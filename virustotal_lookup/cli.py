from . import extract
from . import report
from . import config


def run():
    entities = extract.extract_entities()

    print("\nAvailable entity types for querying:")
    entity_options = []
    for entity_type, entity_list in entities.items():
        count = len(entity_list)
        if count > 0:
            print(f"{len(entity_options) + 1}. {entity_type}: {count} found")
        else:
            print(f"{len(entity_options) + 1}. {entity_type}: None found")
        entity_options.append(entity_type)

    print(f"{len(entity_options) + 1}. All")
    print(f"{len(entity_options) + 2}. Exit")

    while True:
        try:
            user_input = input("\nEnter the numbers of the types you want to query (comma-separated): ")
            if user_input.strip() == str(len(entity_options) + 2):
                print(f"Exiting. Cleaned entity list available at {config.output_file_path}.")
                return
            if user_input.strip() == str(len(entity_options) + 1):
                selected_entities = {etype: entities[etype] for etype in entity_options if entities[etype]}
                break
            selected_indices = {int(x.strip()) - 1 for x in user_input.split(',')}
            selected_entities = {entity_options[i]: entities[entity_options[i]] for i in selected_indices if i < len(entity_options) and entities[entity_options[i]]}
            if selected_entities:
                break
            print("No valid types selected. Please try again.")
        except (ValueError, IndexError):
            print("Invalid input. Please enter numbers corresponding to entity types.")

    if selected_entities:
        print("Starting VirusTotal queries...")
        report.get_reports(selected_entities)
        print(f"Report saved to {config.report_file_path}")
    else:
        print("No entities available for querying.")
