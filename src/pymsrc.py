import requests
import datetime
import json
import pandas as pd
import logging

'''
LOGGING
'''
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(name)s (%(levelname)s) %(message)s')
    logger = logging.getLogger(__name__)
    return logger

class msrc():

    '''
    '''
    def __init__(self, year:int=None, month:int=None) -> None:
        self.msrc_url = "https://api.msrc.microsoft.com/sug/v2.0/en-us/vulnerability"
        self.year = year
        self.month = month
        self.date_patch_tuesday = self.get_last_patch_tuesday_date()
        self.logger = setup_logging()

    '''
    '''
    def get_last_patch_tuesday_date(self) -> datetime :
        today = datetime.date.today()
        if not self.year:
            self.year = today.year
        if not self.month:
            self.month = today.month

        # Patch Tuesday is the second Tuesday of every month
        # Starting at 8, we're sure we've already spent a week
        for day in range(8, 15):
            if datetime.date(self.year, self.month, day).weekday() == 1:
                second_tuesday = datetime.date(self.year, self.month, day)
                break

        # If the second Tuesday is today or in the past, return this date
        if second_tuesday and second_tuesday <= today:
            return second_tuesday.isoformat()
        else:
            # Otherwise, calculate for the previous month
            if self.month == 1:
                self.year -= 1
                self.month = 12
            else:
                self.month -= 1
            
            for day in range(8, 15):
                if datetime.date(self.year, self.month, day).weekday() == 1:
                    second_tuesday = datetime.date(self.year, self.month, day)
                    break
            
            return second_tuesday.isoformat()
        

    '''
    '''
    def get_vulnerabilities(self) -> json:
        headers = {
            'Content-Type': 'application/json'
        }

        # Parameters for the API request
        start_date = str(self.date_patch_tuesday) + "T00:00:00Z"
        end_date = str(self.date_patch_tuesday) + "T23:59:59Z"

        params = {
            "$filter": f"releaseDate ge {start_date} and releaseDate le {end_date}"
        }

        response = requests.get(self.msrc_url, headers=headers, params=params)

        #response.raise_for_status()

        return response.json()
    

    '''
    '''
    def filter_patch_tuesday_vulnerabilities(self, vulnerabilities:json) -> list:
        self.logger.info(f"len(vulnerabilities) : {len(vulnerabilities.get('value', []))}")
        patch_tuesday_vulnerabilities = []
        for vulnerability in vulnerabilities.get('value', []):
            release_date = vulnerability.get('releaseDate', '')
            if release_date.startswith(self.date_patch_tuesday):
                patch_tuesday_vulnerabilities.append(vulnerability)
        self.logger.info(f"len(patch_tuesday_vulnerabilities) : {len(patch_tuesday_vulnerabilities)}")
        return patch_tuesday_vulnerabilities
        

    '''
    '''
    def vulnerabilities_to_json(self, patch_tuesday_vulnerabilities:list, file_name:str):
        vulnerabilities = []
        for vulnerability in patch_tuesday_vulnerabilities:
            vuln_info = {
                "ID": vulnerability.get('id'),
                "CVE Number": vulnerability.get('cveNumber'),
                "Base Score": vulnerability.get('baseScore'),
                "Temporal Score": vulnerability.get('temporalScore'),
                "CVE Title": vulnerability.get('cveTitle'),
                "Vuln Type": vulnerability.get('vulnType'),
                "Release Number": vulnerability.get('releaseNumber'),
                "Latest Revision Date": vulnerability.get('latestRevisionDate'),
                "Release Date": vulnerability.get('releaseDate'),
                "CWE List": vulnerability.get('cweList'),
                "MITRE Text": vulnerability.get('mitreText'),
                "MITRE URL": vulnerability.get('mitreUrl'),
                "Publicity Disclosed": vulnerability.get('publiclyDisclosed'),
                "Exploited": vulnerability.get('exploited'),
                "Tag": vulnerability.get('tag'),
                "Severity": vulnerability.get('severity'),
                "Vector String": vulnerability.get('vectorString'),
                "Impact": vulnerability.get('impact')
            }
            vulnerabilities.append(vuln_info)

        # Output file path
        output_file = f"{self.date_patch_tuesday}-{file_name}.json"

        # Write data to a JSON file
        with open(output_file, 'w') as json_file:
            json.dump(vulnerabilities, json_file, indent=4)


    '''
    '''
    def vulnerabilities_to_excel(self, vulnerabilities:list, file_name:str):
        # Convert dictionary list to DataFrame pandas
        df = pd.DataFrame(vulnerabilities)

        # Export DataFrame to Excel file
        output_file = f"{self.date_patch_tuesday}-{file_name}.xlsx"
        df.to_excel(output_file, index=False) 


