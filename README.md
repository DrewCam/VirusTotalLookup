# VirusTotal Lookup

## Introduction
The VirusTotal Lookup is a Python script that extracts and filters MD5, SHA1, SHA256 hashes, IPv4, IPv6 addresses, and domains from a raw input file (`raw.txt`). It removes internal IPs and prompts the user to select entity types for VirusTotal analysis. The script generates a report in `virustotal_report.txt`, summarizing detection status, reputation, tags, location, and organization details for queried entities.

## Getting Started

### Prerequisites
- Python 3.x
- `requests` library
- `python-dotenv` library

### Installation
1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

3. Create a `.env` file in the project directory and add your VirusTotal API key:
    ```env
    VT_API_KEY=your_virustotal_api_key
    ```

## Usage
1. Add the entities (hashes, IPs, domains) to `raw.txt`.

2. Run the script:
    ```sh
    python VirusTotalLookup.py
    ```

3. Follow the prompts to select the entity types you want to query.

4. The report will be generated in `virustotal_report.txt`.

## Contribute
Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Create a new Pull Request.

## License
This project is licensed under the MIT License.

## Acknowledgements
- [VirusTotal](https://www.virustotal.com) for their API.
- [Python](https://www.python.org) for the programming language.
- [requests](https://docs.python-requests.org/en/master/) library for HTTP requests.
- [python-dotenv](https://saurabh-kumar.com/python-dotenv/) library for managing environment variables.

For more information, refer to the [guidelines](https://docs.microsoft.com/en-us/azure/devops/repos/git/create-a-readme?view=azure-devops).
