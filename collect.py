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


#1 write a function that takes a DBMS name and version
#asks the NVD API for its CVEs (use the requests library)
# NVD API docs: https://nvd.nist.gov/developers/vulnerabilities

#2 for each CVE, keep only the CVE ID and the CVSS score

#3 if a score is missing or not a number, use 5

#4 save the result as a CSV in the csv_files folder
#name it like  mongodb_4.4.csv

# 5 if the API fails, print a message instead of crashing
