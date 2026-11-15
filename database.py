# These are the necessary imports for the database program.
import mysql.connector
import pandas as pd
from getpass import getpass

# The function to connect to the database, assuming your password credentials are correct.
def connect_to_database(password):
    connection = mysql.connector.connect(
        host = "localhost",
        port = 3306,
        user = "root",
        password = password,
    )

    cursor = None
    try:
        cursor = connection.cursor()
        cursor.execute("""
            CREATE DATABASE IF NOT EXISTS nosql_cve_risk
        """)
        connection.database = "nosql_cve_risk"
        return connection

    except Exception:
        connection.close()
        raise

    finally:
        if cursor is not None:
            cursor.close()

# This function creates the tables for this project if the password check is passed on run.
def create_tables(connection):
    cursor = connection.cursor()

    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS `Database` (
                DB_ID INT AUTO_INCREMENT PRIMARY KEY,
                DB_Name VARCHAR(50) NOT NULL,
                DB_Version VARCHAR(50) NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS `CVE` (
                CVE_ID VARCHAR(50) PRIMARY KEY,
                CVSS DECIMAL(3, 1),
                CVE_Desc TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS `Record` (
                DB_ID INT,
                CVE_ID VARCHAR(50),

                PRIMARY KEY (DB_ID, CVE_ID),

                FOREIGN KEY (DB_ID) REFERENCES `Database` (DB_ID),
                FOREIGN KEY (CVE_ID) REFERENCES `CVE` (CVE_ID)
            )
        """)

        print("Database tables have successfully been created and setup!")

    finally:
        cursor.close()

# This function reads the pulled data from the NVD and performs several checks to ensure that
# the data pulled is valid and what we need.
def read_cve_csv(csv_path):
    # This portion of the function is to read the CSV data pulled from the NVD. There are
    # also defined "required_columns" which the CSV must have in order to be read.
    df = pd.read_csv(csv_path, dtype = str, keep_default_na = False)
    required_columns = ["DBMS", "Version", "CVE_ID", "CVSS_Score", "Date_Collected"]

    # This portion of the function checks each column to see if the required columns are
    # in the read CSV. If the CSV is missing one of these columns, an error is raised.
    for column in required_columns:
        if column not in df.columns:
            raise ValueError(f"The CSV is missing a required column: {column}")

        # This portion of the code checks for any empty values within the CSV columns. If
        # there are any empty values, an error is raised.
        df[column] = df[column].str.strip()
        if (df[column] == "").any():
            raise ValueError(f"An empty value has been found in the column: {column}")

    # If the data pulled is empty, this check will raise an error.
    if df.empty:
        raise ValueError("The CSV has no records.")

    # This portion of the function checks that the pulled DBMS from the CSV is either
    # "mongodb" or "cassandra", as those are the focuses of this project.
    df["DBMS"] = df["DBMS"].str.lower()
    if not df["DBMS"].isin(["mongodb", "cassandra"]).all():
        raise ValueError("The DBMS must be either mongodb or cassandra.")

    # This portion of the function checks to see if all the CVSS_Scores are between
    # 0 and 10, as those are the valid score values.
    df["CVSS_Score"] = pd.to_numeric(df["CVSS_Score"], errors = "raise")
    if not df["CVSS_Score"].between(0, 10).all():
        raise ValueError("CVSS scores must be between 0 and 10.")

    #Finally, the df is returned.
    return df

def import_csv(connection, csv_path):
    records = read_cve_csv(csv_path)
    cursor = connection.cursor()

    try:
        for _, row in records.iterrows():
            cursor.execute("""
                SELECT DB_ID FROM `Database` WHERE DB_Name = %s AND DB_Version = %s
            """, (row["DBMS"], row["Version"]))

            matches = cursor.fetchall()
            if matches:
                db_id = matches[0][0]
            else:
                cursor.execute("""
                    INSERT INTO `Database` (DB_Name, DB_Version) VALUES (%s, %s)
                """, (row["DBMS"], row["Version"]))
                db_id = cursor.lastrowid

            cursor.execute("""
                SELECT CVE_ID FROM `CVE` WHERE CVE_ID = %s
            """, (row["CVE_ID"],))

            if cursor.fetchone() is None:
                cursor.execute("""
                    INSERT INTO `CVE` (CVE_ID, CVSS) VALUES (%s, %s)
                """, (row["CVE_ID"], float(row["CVSS_Score"])))

            cursor.execute("""
                SELECT DB_ID FROM `Record` WHERE DB_ID = %s AND CVE_ID = %s
            """, (db_id, row["CVE_ID"]))

            if cursor.fetchone() is None:
                cursor.execute("""
                    INSERT INTO `Record` (DB_ID, CVE_ID) VALUES (%s, %s)
                """, (db_id, row["CVE_ID"]))

        connection.commit()
        print("CSV import has been completed!")

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()

def get_cves(connection, dbms_name, version):
    cursor = connection.cursor(dictionary = True)

    try:
        cursor.execute("""
            SELECT
                d.DB_Name,
                d.DB_Version,
                c.CVE_ID,
                c.CVSS,
                c.CVE_Desc
            FROM `Database` AS d
            JOIN `Record` AS r ON d.DB_ID = r.DB_ID
            JOIN `CVE` AS c ON r.CVE_ID = c.CVE_ID
            WHERE d.DB_Name = %s AND d.DB_Version = %s
        """, (dbms_name.strip().lower(), version.strip()))

        return cursor.fetchall()

    finally:
        cursor.close()

# This portion is a test environment that prompts the user for their MySQL root password.
# If the password is entered correctly, the connection passes and the tables are created.
# Otherwise, they are denied access.
if __name__ == "__main__":
    connection = None

    try:
        password = getpass("Enter your MySQL root password: ")
        connection = connect_to_database(password)
        print("Connection successful!")
        create_tables(connection)
        # This part is not finished, requires the path selection functionality to work.

    except (mysql.connector.Error, ValueError, OSError) as error:
        print(f"Database connection error: {error}")

    finally:
        if connection is not None:
            connection.close()