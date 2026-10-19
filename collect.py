import requests
import pandas as pd
import os
from datetime import datetime

def fetch_nvd_data():
    print("Wellcome to NVD Data Collection")
    verify = "n"
    while verify == "n":
        dbmsName = ""
        versionNumber = ""
        print("Input 'q' to Quit")
        while not dbmsName: # Checks to make sure a name was entered
            dbmsName = input("Enter DBMS Name ('MongoDB' or 'Cassandra'): ").strip().lower()
            if dbmsName == 'q':
                print("Quiting NVD Data Collection")
                return
        while not versionNumber: # Checks to make sure a number was entered
            versionNumber = input("Enter Version Number (e.g., 5.0, 4.0): ").strip().lower()
            if versionNumber == 'q':
                print("Quiting NVD Data Collection")
                return
        verify = input(f"Is '{dbmsName} {versionNumber}' Correct\ny for Yes n for No: ").strip().lower()
        if verify == 'q':
            print("Quiting NVD Data Collection")
            return

    # NVD API Request Setup
    search_keyword = f"{dbmsName} {versionNumber}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": search_keyword, "resultsPerPage": 50}

    print( f"\nFetching data for {search_keyword} from NVD API...\n")

    # Try to fetch nvd data, graceful response to errors
    try:
        response = requests.get(url, params=params, timeout=15)

        if response.status_code == 429:
            print("Error: NVD API rate limit reached (HTTP 429). Please try again later.")
            return
        elif response.status_code != 200:
            print(f"Error: API returned status code {response.status_code}")
            return

        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")
        return
    
    # Extract vulnerabilities
    vulnerabilities = data.get("vulnerabilities", [])
    
    if not vulnerabilities:
        print(f"No CVE records found for '{search_keyword}'.")
        return

    records = []

    # Process vulnerabilities into CVSS Scores
    for item in vulnerabilities:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "UNKNOWN")

        # Extract CVSS Score, checking v3.1, v3.0, or v2 metrics
        cvss_score = None
        metrics = cve_data.get("metrics", {})

        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_key in metrics:
                try:
                    cvss_score = metrics[metric_key][0]["cvssData"]["baseScore"]
                    break
                except (KeyError, IndexError, TypeError):
                    continue
        
        # If CVSS is missing set it to 5
        if cvss_score is None:
            cvss_score = 5.0

        # Store record
        records.append({
            "DBMS": dbmsName,
            "Version": versionNumber,
            "CVE_ID": cve_id,
            "CVSS_Score": cvss_score,
            "Date_Collected": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    # Convert to Pandas DataFrame 
    df = pd.DataFrame(records)
    
    # export to CSV
    filename = f"csv_files/{dbmsName}_{versionNumber}_cvss.csv".replace(" ", "_")
    
    df.to_csv(filename, index=False)
    print(f"Successfully saved {len(records)} records to {filename}!")