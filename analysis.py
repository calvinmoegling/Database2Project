import pandas as pd
import os

#1 write a function that lists the files in csv_files
def list_csv_files():
    path = "/csv_files" # Path to the folder holding .csv files
    file_list = [] # Names of .csv files will go here

    # Make sure we only get .csv files
    try:
        for filename in os.listdir(path):
            if filename.endswith(".csv"):
                file_list.append(filename)
    except:
        print("Error: csv_files folder could not be found. Please verify folder.")
        return
    
    # Print list of file names
    print(file_list)
    # return file_list # in case we need it

#2 write a function that reads the files the user picked
# and works out Average, Max, and Critical Count (score of 9 or more)

def get_csv_info(files_selected): # files_selected is a list of file names
    # We will put Average, Max, etc. for each file into the "data" list
    data = []

    # Iterate through the selected files one-by-one
    # This assumes that each file is the records for one unique DBMS and version
    for file in files_selected:

        # Read each file into a temporary dataframe
        filepath = "/csv_files/" + file
        try:
            temp_df = pd.read_csv(filepath)
        except:
            print(f"Error: file at {filepath} was not found. Please try again.")
            return

        # Calculate the current file's Average, Max, and Critical Count
        average = temp_df.loc[:, 'CVSS_Score'].mean()
        max = temp_df.loc[:, 'CVSS_Score'].max()
        critical_count = temp_df[temp_df['CVSS_Score'] >= 9.0].count()

        #3 calculate the Risk Score using the formula in the SRS
        risk_score = (0.5 * average) + (0.3 * max) + (0.2 * critical_count)

        #4 return a table (pandas DataFrame) sorted by Risk Score
        #columns: DBMS, Version, Risk Score, Average, Max, Critical Count
        data.append({
            "DBMS": temp_df.at[0, 'DBMS'],
            "Version": temp_df.at[0, 'Version'],
            "Risk Score": risk_score,
            "Average": average,
            "Max": max,
            "Critical Count": critical_count
        })

    # Return all of this information in a dataframe
    df = pd.DataFrame(data)
    return df
