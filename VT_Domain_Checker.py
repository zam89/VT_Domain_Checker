import requests
import datetime
import sys
import csv
import os

def timestamp_to_date(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def save_to_csv(data, filename):
    with open(filename, 'a', newline='') as csvfile:
        fieldnames = ['domain', 'VT Link', 'last_analysis_date', 'last_dns_records_date', 'harmless', 'malicious', 'suspicious', 'undetected', 'timeout']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if csvfile.tell() == 0:
            writer.writeheader()
        writer.writerow(data)

def check_domain(domain, csv_output=None, print_output=True):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": "<API_KEY>"
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    if 'data' in data and 'attributes' in data['data']:
        attributes = data['data']['attributes']

        vt_link = f"https://www.virustotal.com/gui/domain/{domain}/detection"
        last_analysis_date = timestamp_to_date(attributes.get('last_analysis_date', 0))
        last_dns_records_date = timestamp_to_date(attributes.get('last_dns_records_date', 0))
        last_analysis_stats = attributes.get('last_analysis_stats', {})

        if print_output:
            print(f"Domain: {domain}")
            print(f"VT Link: {vt_link}")
            print(f"last_analysis_date: {last_analysis_date}")
            print(f"last_dns_records_date: {last_dns_records_date}")
            print("last_analysis_stats: ")
            for key, value in last_analysis_stats.items():
                print(f"    {key}: {value}")
        else:
            print(f"Processing domain: {domain}")

        if csv_output:
            csv_data = {
                "domain": domain,
                "VT Link": vt_link,
                "last_analysis_date": last_analysis_date,
                "last_dns_records_date": last_dns_records_date,
                **last_analysis_stats
            }
            save_to_csv(csv_data, csv_output)

def main():
    csv_output = None
    print_output = True

    if "-d" in sys.argv:
        try:
            domain_index = sys.argv.index("-d")
            domain = sys.argv[domain_index + 1]
        except IndexError:
            print("Error: No domain provided.")
            sys.exit(1)

        if "--csv" in sys.argv:
            try:
                csv_index = sys.argv.index("--csv")
                csv_output = sys.argv[csv_index + 1]
                print_output = False
            except IndexError:
                print("Error: No filename provided for CSV output.")
                sys.exit(1)

        check_domain(domain, csv_output, print_output)

    elif "-f" in sys.argv:
        try:
            file_index = sys.argv.index("-f")
            filename = sys.argv[file_index + 1]
        except IndexError:
            print("Error: No filename provided.")
            sys.exit(1)

        if "--csv" in sys.argv:
            try:
                csv_index = sys.argv.index("--csv")
                csv_output = sys.argv[csv_index + 1]
                print_output = False
            except IndexError:
                print("Error: No filename provided for CSV output.")
                sys.exit(1)

        with open(filename, 'r') as file:
            domains = file.readlines()
            for domain in domains:
                domain = domain.strip()
                if domain:
                    check_domain(domain, csv_output, print_output)

    else:
        print("Usage: python VT_Domain_Checker.py -d [domain] or -f [filename] [--csv filename.csv]")
        sys.exit(1)

    if csv_output:
        full_path = os.path.abspath(csv_output)
        print(f"File saved at: {full_path}")

if __name__ == "__main__":
    main()
