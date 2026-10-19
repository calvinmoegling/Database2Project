def fetch_nvd_data():
    print("Wellcome to NVD Data Collection")
    dbms = ""
    while not(dbms == 'test' or dbms == 'q'): # This checks to make sure the inputed cpe name is in the proper format or it will repeat
        dbms = input("Enter CPE Name (add more detail) or 'q' to exit: ").strip().lower()
    if(dbms == 'q'):
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
