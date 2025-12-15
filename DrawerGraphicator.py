import datetime
import json
import os
import re
import tabulate # https://pypi.org/project/tabulate/
import argparse
import plotly.io as pio
import plotly.graph_objects as go

# Variables 

# Input 

Input_JSON_Path = None # sys.argv[1] # Probably better to argparse it + easier to sanitize https://docs.python.org/3/library/argparse.html

# Time

now = datetime.datetime.now()
datestr = "Generated at: " + now.strftime("%d-%m-%Y %H:%M:%S %p") + "\n"
filedatestr = str(now.strftime("%d-%m-%Y %H%M%S %p")) # Remove the ':' within the string, otherwise we won't be able to save the file. 
versionstr = "v0.15"

Last_Year = (datetime.datetime.now().year) - 1
Current_Year = datetime.datetime.now().year # "%Y-%m-%d%H:%M:%S.%f%Z")

# Tactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"] # This is a per MITRE, 14, Microsoft does it a little different.
Tactics = ["Command and Control", "Lateral Movement", "Malware", "Persistence", "Privilege Escalation", "Ransomware", "Suspicious Activity", "Unwanted Software", "Exploit", "Initial Access", "Execution", "Exfiltration", "Collection", "Credential Access", "Defense Evasion", "Discovery", "Impact"] # This is a per Microsoft, 15, doing them in order.  
Enabled_Rules = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None]
Disabled_Rules = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None]
Enabled_Rules_By_Tactic = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]
Disabled_Rules_By_Tactic = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]

Rules_Created_This_Year_Quarter = [0, 0, 0, 0] # Changed the concept from "None" to "0", to avoid re-initializing it. 
Rules_Created_Last_Year_Quarter = [0, 0, 0, 0]
Rules_Created_This_Year_Group = [[], [], [], []]
Rules_Created_Last_Year_Group = [[], [], [], []]

Rules_Last_Updated_Labels = ["more than 365 days", "between 365 and 180 days", "between 180 and 90 days", "less than 90 days"]
Rules_Last_Updated_Count = [0, 0, 0, 0] # Changed the concept from "None" to "0", to avoid re-initializing it. 
Rules_Last_Updated_Group = [[], [], [], []]

# Counters and similar 

Rule_Counter = 0
Rule_Enabled_Counter = 0
Rule_Disabled_Counter = 0

Command_and_Control_Counter_Enabled = 0
Lateral_Movement_Counter_Enabled = 0 
Malware_Counter_Enabled = 0 
Persistence_Counter_Enabled = 0 
Privilege_Escalation_Counter_Enabled = 0
Ransomware_Counter_Enabled = 0
Suspicious_Activity_Counter_Enabled = 0
Unwanted_Software_Counter_Enabled = 0
Exploit_Counter_Enabled = 0
Initial_Access_Counter_Enabled = 0
Execution_Counter_Enabled = 0
Exfiltration_Counter_Enabled = 0
Collection_Counter_Enabled = 0
Credential_Access_Counter_Enabled = 0
Defense_Evasion_Counter_Enabled = 0
Discovery_Counter_Enabled = 0
Impact_Counter_Enabled = 0

Command_and_Control_Counter_Disabled = 0
Lateral_Movement_Counter_Disabled = 0 
Malware_Counter_Disabled = 0 
Persistence_Counter_Disabled = 0 
Privilege_Escalation_Counter_Disabled = 0
Ransomware_Counter_Disabled = 0
Suspicious_Activity_Counter_Disabled = 0
Unwanted_Software_Counter_Disabled = 0
Exploit_Counter_Disabled = 0
Initial_Access_Counter_Disabled = 0
Execution_Counter_Disabled = 0
Exfiltration_Counter_Disabled = 0
Collection_Counter_Disabled = 0
Credential_Access_Counter_Disabled = 0
Defense_Evasion_Counter_Disabled = 0
Discovery_Counter_Disabled = 0
Impact_Counter_Disabled = 0

# Patterns (Usually follows pascal case as DefenseEvasion, but just in case we are paranoid we match everything and if it fails, review)

Command_and_Control_Pattern = r'CommandAndControl'
Lateral_Movement_Pattern = r'LateralMovement'
Malware_Pattern = r'Malware'
Persistence_Pattern = r'Persistence' 
Privilege_Pattern = r'Privilege'
Ransomware_Pattern = r'Ransomware'
Suspicious_Activity_Pattern = r'SuspiciousActivity'
Unwanted_Software_Pattern = r'UnwantedSoftware'
Exploit_Pattern = r'Exploit'
Initial_Access_Pattern = r'InitialAccess'
Execution_Pattern = r'Execution'
Exfiltration_Pattern = r'Exfiltration'
Collection_Pattern = r'Collection'
Credential_Access_Pattern = r'CredentialAccess'
Defense_Evasion_Pattern = r'DefenseEvasion'
Discovery_Pattern = r'Discovery'
Impact_Pattern = r'Impact'

Rule_ID_Pattern = r'\'id\': \'[0-9]{4,6}\''
Rule_Enabled_Pattern = r'True'

DateTimePattern = r'[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}T[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}'
RogueNewLinesPattern=r'^\n| $'
EOFKQLString = r'(\r|\n)$'

# These are the "Ingestion" functions, where data is acquired to generate the graphics. 

Graphic_One = None
Graphic_Two = None
Graphic_Three = None
Graphic_Four = None
Graphic_Five = None
Graphic_Six = None
Graphic_Seven = None

# https://graph.microsoft.com/beta/security/rules/detectionRules?$select=id Only shows a % of what are already created, which is bizarre. 

def Argument_Parser():
    global Input_JSON_Path
    parser = argparse.ArgumentParser(description='A small script to give you some insights into your detection rules.')
    parser.add_argument('input_file', help='The raw file containing your detection rules.')
 
    args = parser.parse_args()
 
    Input_JSON_Path = args.input_file
    # Debug
    # print(f"Input file: {args.input_file}")

def Ingest_CSV(): # WIP
    pass 

def Ingest_JSON(Input_JSON_Path):
    # How to create your file: 
    # Needs to be authenticated, either with a secret or a token, and have the "CustomDetection.Read.All" permission.  
    # Invoke-WebRequest "https://graph.microsoft.com/beta/security/rules/detectionRules" -ContentType "application/json" -Method GET
    # You can pre-filter in the request itself, or just sent the raw file. 

    isFile = os.path.isfile(Input_JSON_Path)
    print("Procesing file: ", str(Input_JSON_Path))
    print("File path validity returns: ", isFile)
    print("Working...")

    # FilePath = 'File.txt' #
    global Rule_Counter, Rule_Enabled_Counter, Rule_Disabled_Counter
    with open(Input_JSON_Path, 'r') as file: # Replace with FilePath for local debugging.
        data = json.load(file)
        # print(str(data['value'][0]['id']))
        # print(str(len(data['value'][0]['id'])))
        
        # Calculate how many IDs are inside of "value". This is to later determine how many rules you exported, vs how we ingested vs how many we used on a graph, and see if we missed anything. 
        
        ValueString = str(data['value'])
        # print("Value is: ", ValueString)
        Rule_ID_Search = re.findall(Rule_ID_Pattern, ValueString)
        NumberOfRules = len(Rule_ID_Search)
        
        print("Number of detected rules: " + str(NumberOfRules))
        while (NumberOfRules) > Rule_Counter:
            # Rule_Enabled_Search = re.search(Rule_Enabled_Pattern, data['value'][Rule_Counter]['isEnabled'])
            if(data['value'][Rule_Counter]['isEnabled'] == True):
                LogLineEnabled = "Processing enabled rule: " + data['value'][Rule_Counter]['displayName'] + " with id: " + str(data['value'][Rule_Counter]['id'])
                print(LogLineEnabled)                
                Validate_Tactic(data['value'][Rule_Counter]['detectionAction']['alertTemplate']['category'], data['value'][Rule_Counter]['displayName'], data['value'][Rule_Counter]['id'], "True")
                Validate_Dates(now, data['value'][Rule_Counter]['createdDateTime'], data['value'][Rule_Counter]['lastModifiedDateTime'], data['value'][Rule_Counter]['displayName'], data['value'][Rule_Counter]['id'])
                Validate_QueryText(data['value'][Rule_Counter]['queryCondition']['queryText'], data['value'][Rule_Counter]['displayName'], data['value'][Rule_Counter]['id'], "True")
                Rule_Enabled_Counter = Rule_Enabled_Counter + 1
            else: 
                LogLineDisabled = "Processing disabled rule: " + data['value'][Rule_Counter]['displayName'] + " with id: " + str(data['value'][Rule_Counter]['id'])
                print(LogLineDisabled)   
                Validate_Tactic(data['value'][Rule_Counter]['detectionAction']['alertTemplate']['category'], data['value'][Rule_Counter]['displayName'], data['value'][Rule_Counter]['id'], "False")
                Validate_Dates(now, data['value'][Rule_Counter]['createdDateTime'], data['value'][Rule_Counter]['lastModifiedDateTime'], data['value'][Rule_Counter]['displayName'], data['value'][Rule_Counter]['id'])
                Validate_QueryText(data['value'][Rule_Counter]['queryCondition']['queryText'], data['value'][Rule_Counter]['displayName'], data['value'][Rule_Counter]['id'], "False")
                Rule_Disabled_Counter = Rule_Disabled_Counter + 1

            Rule_Counter = Rule_Counter + 1

            # Debug 
            # print(str(len(data))) # Careful, the len(data) is usually 3, because you get Odata x2 + "value". This is why you have to enumerate every single string on data['value'] to confirm how many rules you grabbed. 
            # print(data['value'][0]) # Wor
            # So, for each subkey within "value"[x] we search for all of the following:
            # print("Rule counter is:", str(Rule_Counter))
            # print(data['value'][Rule_Counter]['detectorId'])
            # print(data['value'][Rule_Counter]['id'])
            # print(data['value'][Rule_Counter]['displayName'])
            # print(data['value'][Rule_Counter]['isEnabled'])
            # print(data['value'][Rule_Counter]['createdDateTime'])
            # print(data['value'][Rule_Counter]['lastModifiedDateTime'])
            # print(data['value'][Rule_Counter]['queryCondition']['queryText']) # This might have more than one key? (Due to old changes, from time to time)
            # print(data['value'][Rule_Counter]['detectionAction']['alertTemplate']['description'])
            # print(data['value'][Rule_Counter]['detectionAction']['alertTemplate']['severity'])
            # print(data['value'][Rule_Counter]['detectionAction']['alertTemplate']['category'])
            # print(data['value'][Rule_Counter]['detectionAction']['alertTemplate']['recommendedActions']) 
            # print(data['value'][Rule_Counter]['detectionAction']['alertTemplate']['mitreTechniques'])
      
# These are data validation functions

def Validate_Tactic(data, displayName, id, Status):
    # This is probably not needed at all, and wasting some processing. However, I was overly paranoid about not getting the correct string or it being formmatted wrong, so I pulled this up to validate each specific case.
    
    Command_and_Control_Search = re.search(Command_and_Control_Pattern, data)
    Lateral_Movement_Search = re.search(Lateral_Movement_Pattern, data)
    Malware_Search = re.search(Malware_Pattern, data)
    Persistence_Search = re.search(Persistence_Pattern, data)
    Privilege_Escalation_Search = re.search(Privilege_Pattern, data)
    Ransomware_Search = re.search(Ransomware_Pattern, data)
    Suspicious_Activity_Search = re.search(Suspicious_Activity_Pattern, data)
    Unwanted_Software_Search = re.search(Unwanted_Software_Pattern, data)
    Exploit_Search = re.search(Exploit_Pattern, data)
    Initial_Access_Search = re.search(Initial_Access_Pattern, data)
    Execution_Search = re.search(Execution_Pattern, data)
    Exfiltration_Search = re.search(Exfiltration_Pattern, data)
    Collection_Search = re.search(Collection_Pattern, data)
    Credential_Access_Search = re.search(Credential_Access_Pattern, data)
    Defense_Evasion_Search = re.search(Defense_Evasion_Pattern, data)
    Discovery_Search = re.search(Discovery_Pattern, data)
    Impact_Search = re.search(Impact_Pattern, data)
    
    if(Command_and_Control_Search):
        global Command_and_Control_Counter_Enabled, Command_and_Control_Counter_Disabled
        if(Status == "True"):
            Command_and_Control_Counter_Enabled = Command_and_Control_Counter_Enabled + 1
            Enabled_Rules[0] = Command_and_Control_Counter_Enabled
            Enabled_Rules_By_Tactic[0].append(id) # Replace this with id, the idea is that you don't have to transverse the entire chunk to get what you need. 
        else:
            Command_and_Control_Counter_Disabled = Command_and_Control_Counter_Disabled + 1
            Disabled_Rules[0] = Command_and_Control_Counter_Disabled
            Disabled_Rules_By_Tactic[0].append(id)
    elif(Lateral_Movement_Search):
        global Lateral_Movement_Counter_Enabled, Lateral_Movement_Counter_Disabled
        if(Status == "True"):
            Lateral_Movement_Counter_Enabled = Lateral_Movement_Counter_Enabled + 1
            Enabled_Rules[1] = Lateral_Movement_Counter_Enabled
            Enabled_Rules_By_Tactic[1].append(id)
        else:
            Lateral_Movement_Counter_Disabled = Lateral_Movement_Counter_Disabled + 1
            Disabled_Rules[1] = Lateral_Movement_Counter_Disabled
            Disabled_Rules_By_Tactic[1].append(id)
    elif(Malware_Search):
        global Malware_Counter_Enabled, Malware_Counter_Disabled
        if(Status == "True"):
            Malware_Counter_Enabled = Malware_Counter_Enabled + 1
            Enabled_Rules[2] = Malware_Counter_Enabled
            Enabled_Rules_By_Tactic[2].append(id)
        else:
            Malware_Counter_Disabled = Malware_Counter_Disabled + 1
            Disabled_Rules[2] = Malware_Counter_Disabled
            Disabled_Rules_By_Tactic[2].append(id)
    elif(Persistence_Search):
        global Persistence_Counter_Enabled, Persistence_Counter_Disabled
        if(Status == "True"):
            Persistence_Counter_Enabled = Persistence_Counter_Enabled + 1
            Enabled_Rules[3] = Persistence_Counter_Enabled
            Enabled_Rules_By_Tactic[3].append(id)
        else:
            Persistence_Counter_Disabled = Persistence_Counter_Disabled + 1
            Disabled_Rules[3] = Persistence_Counter_Disabled
            Disabled_Rules_By_Tactic[3].append(id)
    elif(Privilege_Escalation_Search):
        global Privilege_Escalation_Counter_Enabled, Privilege_Escalation_Counter_Disabled
        if(Status == "True"):
            Privilege_Escalation_Counter_Enabled = Privilege_Escalation_Counter_Enabled + 1
            Enabled_Rules[4] = Privilege_Escalation_Counter_Enabled
            Enabled_Rules_By_Tactic[4].append(id)
        else:
            Privilege_Escalation_Counter_Disabled = Privilege_Escalation_Counter_Disabled + 1
            Disabled_Rules[4] = Privilege_Escalation_Counter_Disabled
            Disabled_Rules_By_Tactic[4].append(id)
    elif(Ransomware_Search):
        global Ransomware_Counter_Enabled, Ransomware_Counter_Disabled
        if(Status == "True"):
            Ransomware_Counter_Enabled = Ransomware_Counter_Enabled + 1
            Enabled_Rules[5] = Ransomware_Counter_Enabled
            Enabled_Rules_By_Tactic[5].append(id)
        else:
            Ransomware_Counter_Disabled = Ransomware_Counter_Disabled + 1
            Disabled_Rules[5] = Ransomware_Counter_Disabled
            Disabled_Rules_By_Tactic[5].append(id)
    elif(Suspicious_Activity_Search):
        global Suspicious_Activity_Counter_Enabled, Suspicious_Activity_Counter_Disabled
        if(Status == "True"):
            Suspicious_Activity_Counter_Enabled = Suspicious_Activity_Counter_Enabled + 1
            Enabled_Rules[6] = Suspicious_Activity_Counter_Enabled
            Enabled_Rules_By_Tactic[6].append(id)
        else:
            Suspicious_Activity_Counter_Disabled = Suspicious_Activity_Counter_Disabled + 1
            Disabled_Rules[6] = Suspicious_Activity_Counter_Disabled
            Disabled_Rules_By_Tactic[6].append(id)
    elif(Unwanted_Software_Search):
        global Unwanted_Software_Counter_Enabled, Unwanted_Software_Counter_Disabled
        if(Status == "True"):
            Unwanted_Software_Counter_Enabled = Unwanted_Software_Counter_Enabled + 1
            Enabled_Rules[7] = Unwanted_Software_Counter_Enabled
            Enabled_Rules_By_Tactic[7].append(id)
        else:
            Unwanted_Software_Counter_Disabled = Unwanted_Software_Counter_Disabled + 1
            Disabled_Rules[7] = Unwanted_Software_Counter_Disabled
            Disabled_Rules_By_Tactic[7].append(id)
    elif(Exploit_Search):
        global Exploit_Counter_Enabled, Exploit_Counter_Disabled
        if(Status == "True"):
            Exploit_Counter_Enabled = Exploit_Counter_Enabled + 1
            Enabled_Rules[8] = Exploit_Counter_Enabled
            Enabled_Rules_By_Tactic[8].append(id)
        else:
            Exploit_Counter_Disabled = Exploit_Counter_Disabled + 1
            Disabled_Rules[8] = Exploit_Counter_Disabled
            Disabled_Rules_By_Tactic[8].append(id)
    elif(Initial_Access_Search):
        global Initial_Access_Counter_Enabled, Initial_Access_Counter_Disabled
        if(Status == "True"):
            Initial_Access_Counter_Enabled = Initial_Access_Counter_Enabled + 1
            Enabled_Rules[9] = Initial_Access_Counter_Enabled
            Enabled_Rules_By_Tactic[9].append(id)
        else:
            Initial_Access_Counter_Disabled = Initial_Access_Counter_Disabled + 1
            Disabled_Rules[9] = Initial_Access_Counter_Disabled
            Disabled_Rules_By_Tactic[9].append(id)
    elif(Execution_Search):
        global Execution_Counter_Enabled, Execution_Counter_Disabled
        if(Status == "True"):    
            Execution_Counter_Enabled = Execution_Counter_Enabled + 1
            Enabled_Rules[10] = Execution_Counter_Enabled
            Enabled_Rules_By_Tactic[10].append(id)
        else:
            Execution_Counter_Disabled = Execution_Counter_Disabled + 1
            Disabled_Rules[10] = Execution_Counter_Disabled
            Disabled_Rules_By_Tactic[10].append(id)
    elif(Exfiltration_Search):
        global Exfiltration_Counter_Enabled, Exfiltration_Counter_Disabled
        if(Status == "True"):
            Exfiltration_Counter_Enabled = Exfiltration_Counter_Enabled + 1
            Enabled_Rules[11] = Exfiltration_Counter_Enabled
            Enabled_Rules_By_Tactic[11].append(id)
        else:
            Exfiltration_Counter_Disabled = Exfiltration_Counter_Disabled + 1
            Disabled_Rules[11] = Exfiltration_Counter_Disabled
            Disabled_Rules_By_Tactic[11].append(id)
    elif(Collection_Search):
        global Collection_Counter_Enabled, Collection_Counter_Disabled
        if(Status == "True"):
            Collection_Counter_Enabled = Collection_Counter_Enabled + 1
            Enabled_Rules[12] = Collection_Counter_Enabled
            Enabled_Rules_By_Tactic[12].append(id)
        else:
            Collection_Counter_Disabled = Collection_Counter_Disabled + 1
            Disabled_Rules[12] = Collection_Counter_Disabled
            Disabled_Rules_By_Tactic[12].append(id)
    elif(Credential_Access_Search):
        global Credential_Access_Counter_Enabled, Credential_Access_Counter_Disabled
        if(Status == "True"):
            Credential_Access_Counter_Enabled = Credential_Access_Counter_Enabled + 1
            Enabled_Rules[13] = Credential_Access_Counter_Enabled
            Enabled_Rules_By_Tactic[13].append(id)
        else: 
            Credential_Access_Counter_Disabled = Credential_Access_Counter_Disabled + 1
            Disabled_Rules[13] = Credential_Access_Counter_Disabled
            Disabled_Rules_By_Tactic[13].append(id)
    elif(Defense_Evasion_Search):
        global Defense_Evasion_Counter_Enabled, Defense_Evasion_Counter_Disabled
        if(Status == "True"):
            Defense_Evasion_Counter_Enabled = Defense_Evasion_Counter_Enabled + 1
            Enabled_Rules[14] = Defense_Evasion_Counter_Enabled
            Enabled_Rules_By_Tactic[14].append(id)
        else:
            Defense_Evasion_Counter_Disabled = Defense_Evasion_Counter_Disabled + 1
            Disabled_Rules[14] = Defense_Evasion_Counter_Disabled
            Disabled_Rules_By_Tactic[14].append(id)
    elif(Discovery_Search):
        global Discovery_Counter_Enabled, Discovery_Counter_Disabled
        if(Status == "True"):
            Discovery_Counter_Enabled = Discovery_Counter_Enabled + 1
            Enabled_Rules[15] = Discovery_Counter_Enabled
            Enabled_Rules_By_Tactic[15].append(id)
        else:
            Discovery_Counter_Disabled = Discovery_Counter_Disabled + 1
            Disabled_Rules[15] = Discovery_Counter_Disabled
            Disabled_Rules_By_Tactic[15].append(id)
    elif(Impact_Search):
        global Impact_Counter_Enabled, Impact_Counter_Disabled
        if(Status == "True"):
            Impact_Counter_Enabled = Impact_Counter_Enabled + 1
            Enabled_Rules[16] = Impact_Counter_Enabled
            Enabled_Rules_By_Tactic[16].append(id)
        else: 
            Impact_Counter_Disabled = Impact_Counter_Disabled + 1
            Disabled_Rules[16] = Impact_Counter_Disabled
            Disabled_Rules_By_Tactic[16].append(id)
    else:
        print("Error: The rule with title: " + str(displayName) + " and ID " + str(id)  + " didn't match any tactic.")

def Validate_Dates(now, createdDateTime, lastModifiedDateTime, displayName, id):
    # Usually formated as: 2025-10-29T18:41:20.3332688Z although it might be subject for change due to your local region/tenant (I'm YYYY-MM-DD, and you might be YYYY-DD-MM, etc)
    # Case 1: createdDateTime = lastModifiedDateTime, never modified after creation. 
    # Case 2: createdDateTime < lastModifiedDateTime, created and later modified 
    # Case 3: createdDateTime > lastModifiedDateTime, should never happen, probably a bug. 
    global Last_Year, Current_Year

    # Stripping some seconds that are not needed, and making it "leaner" # [2025-10-29T18:41:20].3332688Z
    Stripped_Created_Date_Time = re.search(DateTimePattern, createdDateTime)
    Stripped_Modified_Date_Time = re.search(DateTimePattern, lastModifiedDateTime)

    Created_Date_Time = datetime.datetime.strptime(Stripped_Created_Date_Time.group(), "%Y-%m-%dT%H:%M:%S")
    Modified_Date_Time = datetime.datetime.strptime(Stripped_Modified_Date_Time.group(), "%Y-%m-%dT%H:%M:%S")
    
    # On which year was this created? 
    # On which quarter? 

    delta = now - Modified_Date_Time
    
    Q1 = [1,2,3]
    Q2 = [4,5,6]
    Q3 = [7,8,9]
    Q4 = [10,11,12]

    if(Created_Date_Time.year == Current_Year):
        if(Created_Date_Time.month in Q1):
            Rules_Created_This_Year_Group[0].append(id)
            Rules_Created_This_Year_Quarter[0] = Rules_Created_This_Year_Quarter[0] + 1
        elif(Created_Date_Time.month in Q2):
            Rules_Created_This_Year_Group[1].append(id)
            Rules_Created_This_Year_Quarter[1] = Rules_Created_This_Year_Quarter[1] + 1
        elif(Created_Date_Time.month in Q3):
            Rules_Created_This_Year_Group[2].append(id)
            Rules_Created_This_Year_Quarter[2] = Rules_Created_This_Year_Quarter[2] + 1
        elif(Created_Date_Time.month in Q4):
            Rules_Created_This_Year_Group[3].append(id)
            Rules_Created_This_Year_Quarter[3] = Rules_Created_This_Year_Quarter[3] + 1
        else:
            print("Something failed!")
    elif(Created_Date_Time.year == Last_Year):
        if(Created_Date_Time.month in Q1):
            Rules_Created_Last_Year_Group[0].append(id)
            Rules_Created_Last_Year_Quarter[0] = Rules_Created_Last_Year_Quarter[0] + 1
        elif(Created_Date_Time.month in Q2):
            Rules_Created_Last_Year_Group[1].append(id)
            Rules_Created_Last_Year_Quarter[1] = Rules_Created_Last_Year_Quarter[1] + 1
        elif(Created_Date_Time.month in Q3):
            Rules_Created_Last_Year_Group[2].append(id)
            Rules_Created_Last_Year_Quarter[2] = Rules_Created_Last_Year_Quarter[2] + 1
        elif(Created_Date_Time.month in Q4):
            Rules_Created_Last_Year_Group[3].append(id)
            Rules_Created_Last_Year_Quarter[3] = Rules_Created_Last_Year_Quarter[3] + 1
        else:
            print("Something failed!")
    else:
        # Discarding all values that are not in the last two years. Later on we will start putting them in "others"
        print("Error: The rule with title: " + str(displayName) + " and ID " + str(id)  + " was older than two years old and discarded.")

    # For the graphic, [red] >365 days, [orange] 180 days, [yellow] 90 days, [green] less than 90 days.
    if(delta.days > 365):
        Rules_Last_Updated_Group[0].append(id)
        Rules_Last_Updated_Count[0] = Rules_Last_Updated_Count[0] + 1
    elif(delta.days <= 365 and delta.days >= 180):
        Rules_Last_Updated_Group[1].append(id)
        Rules_Last_Updated_Count[1] = Rules_Last_Updated_Count[1] + 1
    elif(delta.days < 180 and delta.days >= 90):
        Rules_Last_Updated_Group[2].append(id)
        Rules_Last_Updated_Count[2] = Rules_Last_Updated_Count[2] + 1
    elif(delta.days < 90):
        Rules_Last_Updated_Group[3].append(id)
        Rules_Last_Updated_Count[3] = Rules_Last_Updated_Count[3] + 1

    # Debug
    # print("Pre-parsed created time is: ", createdDateTime)
    # print("Pre-parsed modified time is: ", lastModifiedDateTime)
    # print("Parsed created time is: ", Created_Date_Time)
    # print("Parsed modified time is: ", Modified_Date_Time)

    # Pre-parsed created time is:  2025-11-11T14:32:24.5526325Z
    # Pre-parsed modified time is:  2025-11-12T19:27:01.5409963Z
    # Parsed created time is:  2025-11-11 14:32:24
    # Parsed modified time is:  2025-11-12 19:27:01

def Validate_QueryText(data, displayName, id, Status):
    # Create a dump of the latest query text for each group of rules, so we can use them later. 
    # We also should add a "&" at the end of each line, except the last, so we can construct a functional "queryfile" for KQL. 
    CommentLine = "// displayName: " + displayName + " Id: " + str(id) + " &"
    # ControlLine = "<<-TO BE REMOVED->>" # Used mostly to debug, now just replaced with \n. 
    
    # Sometimes, we get extra \n inside "data" or even during the write process.
    # It is worth nothing that the "querytext" should be as clean as possible from the get-go, without double \n or strange characters mixed in-between. 
    
    Parsed_Result_Stage_1 = re.sub(RogueNewLinesPattern, '', data, flags=re.MULTILINE)
    Parsed_Result_Stage_2 = re.sub(EOFKQLString, ' &', Parsed_Result_Stage_1, flags=re.MULTILINE)
    # Write to filedatestr + AllRulesQueryText.txt
    CompleteFile = open(filedatestr + ' AllRulesQueryText.txt', 'a')
    CompleteFile.write(f"{CommentLine}\n")
    CompleteFile.write(f"{Parsed_Result_Stage_2}\n")
    CompleteFile.write("\n")
    # CompleteFile.write(f"{ControlLine}\n")
    CompleteFile.close()
    # Debug

    if(Status == "True"):
       # Write to filedatestr + EnabledRulesQueryText.txt
       EnabledFiles = open(filedatestr + ' EnabledRulesQueryText.txt', 'a')
       EnabledFiles.write(f"{CommentLine}\n")
       EnabledFiles.write(f"{Parsed_Result_Stage_2}\n")
       EnabledFiles.write("\n")
       # EnabledFiles.write(f"{ControlLine}\n")
       EnabledFiles.close()
    else:
        # Write to filedatestr + DisabledRulesQueryText.txt
        DisabledFiles = open(filedatestr + ' DisabledRulesQueryText.txt', 'a')
        DisabledFiles.write(f"{CommentLine}\n")
        DisabledFiles.write(f"{Parsed_Result_Stage_2}\n")
        DisabledFiles.write("\n")
        # DisabledFiles.write(f"{ControlLine}\n")
        DisabledFiles.close()

# These are the "Drawing" functions, where each graphic is created. 

def Graphic_One(X_Axis_Enabled, Y_Axis_Enabled, X_Axis_Disabled, Y_Axis_Disabled, Enabled_Rules, Disabled_Rules):
    # Chart 1: Comparison of Enabled/Disabled rule count per ATT&CK Core Tactic, Enterprise. (Stacked V.Bar Chart)
    # 14 Columns
    # x axis = Tactics name (As an array of strings ["Recon", "Initial Access"])
    # y axis = Rule number (As an array of ints [1,2])
    # hover axis = Group of rules as (Array of Array [[], [], []]) for EACH group of rules. 
    # Notes: In some cases, where the values are "0" the label will still be drawn, obfuscating some of the text, see: https://community.plotly.com/t/hiding-stacked-scatter-plot-lines-when-value-is-zero/72197/4
    # A solution could be to replace all "0" values with "None", before the drawing begins. 
    fig = go.Figure(data=[
    go.Bar(name='Enabled Rules', x=X_Axis_Enabled, y=Y_Axis_Enabled, text= Y_Axis_Enabled, hovertext=Enabled_Rules),
    go.Bar(name='Disabled Rules', x=X_Axis_Disabled, y=Y_Axis_Disabled, text = Y_Axis_Disabled, hovertext=Disabled_Rules)
    ])
    # Change the bar mode
    fig.update_traces(texttemplate='%{text:,d}', textposition='outside')
    fig.update_layout(barmode='stack')
    # fig.update_layout(uniformtext_minsize=8, uniformtext_mode='hide', xaxis=dict(tickformat=",d"), yaxis=dict(tickformat=",d"))
    global Graphic_One
    Graphic_One = pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

def Graphic_Two(X_Axis, Y_Axis, Hover_Text):
    # Chart 2: Enabled rule count per ATT&CK Core Tactic, Enterprise. (V.Bar Chart)
    # 14 Columns
    # x axis = Tactics name (As an array of strings ["Recon", "Initial Access"])
    # y axis = Rule number (As and array of ints [1,2])
    # hover axis = Group of rules as (Array of Array [[]])
    fig = go.Figure(data=[go.Bar(
            x=X_Axis, y=Y_Axis,
            text=Y_Axis,
            textposition='outside',
            hovertext=Hover_Text
        )])
    fig.update_traces(texttemplate='%{text:,d}', textposition='outside')
    fig.update_layout(uniformtext_minsize=8, uniformtext_mode='hide', xaxis=dict(tickformat=",d"), yaxis=dict(tickformat=",d"))
    # fig.show()
    global Graphic_Two
    Graphic_Two = pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

def Graphic_Three(X_Axis, Y_Axis):
    # Chart 3: Weight of each Tactic in enabled rules (Pie Chart)
    # 14 Pie sections (Tasty!)
    # x axis = Tactics name (As an array of strings ["Recon", "Initial Access"])
    # y axis = Rule number (As and array of ints [1,2])
    fig = go.Figure(data=[go.Pie(labels=X_Axis, values=Y_Axis
    )])
    global Graphic_Three
    Graphic_Three = pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

def Graphic_Four(X_Axis, Y_Axis):
    # Chart 4: Weight of each Tactic in disabled rules (Pie Chart)
    # 14 Pie sections (Tasty!)
    # x axis = Tactics name (As an array of strings ["Recon", "Initial Access"])
    # y axis = Rule number (As and array of ints [1,2])
    fig = go.Figure(data=[go.Pie(labels=X_Axis, values=Y_Axis
    )])
    global Graphic_Four
    Graphic_Four = pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

def Graphic_Five(Last_X_Axis, This_X_Axis, Last_Hover_Text, This_Hover_Text):
    # Chart 5: Rule creation per quarter, last 2 years. (H.Bar Chart) https://plotly.com/python/horizontal-bar-charts/, this one: Small multiple horizontal bar charts show each component's size more clearly than a stacked bar
    # y axis: Labels, per quarter (As an array of strings ["Q1", "Q2"])
    # x axis: Rule count, per quarter (As an array of int [1,2,5])
    # hover: Rule ID created, per quarter (As an array of strings ["92213", "93113"])
    global Last_Year, Current_Year
    Y_Axis = ["Q1", "Q2", "Q3", "Q4"]
    fig = go.Figure(data=[
        go.Bar(name='Last Year', y=Y_Axis, x=Last_X_Axis, hovertext=Last_Hover_Text, xaxis='x', offsetgroup=1, orientation='h'),
        go.Bar(name='This Year', y=Y_Axis, x=This_X_Axis, hovertext=This_Hover_Text, xaxis='x2', offsetgroup=2, orientation='h')
    ],
        layout={
        'xaxis': {'title': 'Last year ' + str(Last_Year)},
        'xaxis2': {'title': 'This year ' + str(Current_Year), 'overlaying': 'x', 'side': 'top'}
    }
    )
    fig.update_layout(barmode='group')
    global Graphic_Five
    Graphic_Five = pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

def Graphic_Six(X_Axis, Y_Axis, Hover_Text):
    # Chart 6: DonutPieChart of rules according to their last update DateTime.
    # color discrete map doesn't work here 
    colors = ["red", "orange", "yellow", "green"]
    fig = go.Figure(data=[go.Pie(labels=X_Axis, values=Y_Axis, hovertext=Hover_Text, hole=.3,     
    )])
    fig.update_traces(marker=dict(colors=colors, line=dict(color='#000000', width=2)))
    global Graphic_Six
    Graphic_Six = pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

def Graphic_Seven():
    # Chart 7: Comparison of rule count by severity (Stacked V.Bar Chart)
    pass

def Build_HTML():
    # The combination of all charts and the corresponding HTML code
    filename = filedatestr + '.html'
    f = open(filename, 'w')
    html_template = """<html>
    <head>
    <title>Title</title>
    </head>
    <body>
    <h1>DetEng Report</h1>
    """ + datestr + """
    <br>
    """ + versionstr + """
    <br>
    Analyzed rules: """ + str(Rule_Counter) + """
    <br>
    Enabled rules: """ + str(Rule_Enabled_Counter) + """
    <br>
    Disabled rules: """ + str(Rule_Disabled_Counter) + """
    <br>
    "Stale" rules (>365 days without review): """ + str(Rules_Last_Updated_Count[0]) + """
    <br>
    <h2>Comparison of Enabled/Disabled rule count per Core Tactic</h2>
    <div id="plotly-graphs-container">
    <!-- Graph 1 -->
    """ + Graphic_One + """
    <br> 
    """ + Enabled_Rules_Tabulated_HTML + """
    """ + Disabled_Rules_Tabulated_HTML + """
    <br>
    <h2>Enabled rule count per Core Tactic</h2>
    <!-- Graph 2-->
    """ + Graphic_Two + """
    Debug: 
    <br>
    """ + Enabled_Rules_Tabulated_HTML + """
    <br>
    <!-- Graph 3-->
    <h2>Weight of each Tactic in Enabled rules</h2>
    """ + Graphic_Three + """ 
    <br>
    """ + Enabled_Rules_Tabulated_HTML + """
    <br>
    <!-- Graph 4-->
    <h2>Weight of each Tactic in Disabled rules</h2>
    """ + Graphic_Four + """
    <br>
    """ + Disabled_Rules_Tabulated_HTML + """
    <br>
    <h2>Rule Creation per quarter, last 2 years</h2>
    """ + Graphic_Five + """
    <br>
    """ + Rule_Creation_This_Year_Tabulated_HTML + """
    """ + Rule_Creation_Last_Year_Tabulated_HTML + """
    <br>
    <h2>Rules according to their last update</h2>
    """ + Graphic_Six + """
    <br>
    """ + Rules_Last_Updated_Tabulated_HTML + """
    <br>
    </div>
    </body>
    </html>
    """
    # writing the code into the file
    f.write(html_template)
    # close the file
    f.close()

    # Debug
    print("Wrote graphical report file: ", filename)

# Here, the logic to use the desired function of data ingestion/analysis. 

Argument_Parser() # Using argparser

print("--------------------------------------------------")
print("Thanks for using My Ill Lackeys in Azure (MILA)!", versionstr)
print("🍞🥩🍞")
print("--------------------------------------------------")

# print("Input args are: ", sys.argv[1])
Ingest_JSON(Input_JSON_Path)

# Here, the logic to enable/disable graphic as per the user setup their config in "DrawerConfig.json"

Graphic_One(Tactics, Enabled_Rules, Tactics, Disabled_Rules, Enabled_Rules_By_Tactic, Disabled_Rules_By_Tactic)
Graphic_Two(Tactics, Enabled_Rules, Enabled_Rules_By_Tactic)
Graphic_Three(Tactics, Enabled_Rules)
Graphic_Four(Tactics, Disabled_Rules)
Graphic_Five(Rules_Created_Last_Year_Quarter, Rules_Created_This_Year_Quarter, Rules_Created_Last_Year_Group, Rules_Created_This_Year_Group)
Graphic_Six(Rules_Last_Updated_Labels, Rules_Last_Updated_Count, Rules_Last_Updated_Group)

# Formatting debug tables so they render nicely for HTML.

Enabled_Rules_Tabulated_HTML = tabulate.tabulate([Enabled_Rules, Enabled_Rules_By_Tactic], headers = ["Command and Control", "Lateral Movement", "Malware", "Persistence", "Privilege Escalation", "Ransomware", "Suspicious Activity", "Unwanted Software", "Exploit", "Initial Access", "Execution", "Exfiltration", "Collection", "Credential Access", "Defense Evasion", "Discovery", "Impact"], missingval="N/A", tablefmt="html")
Disabled_Rules_Tabulated_HTML = tabulate.tabulate([Disabled_Rules, Disabled_Rules_By_Tactic], headers = ["Command and Control", "Lateral Movement", "Malware", "Persistence", "Privilege Escalation", "Ransomware", "Suspicious Activity", "Unwanted Software", "Exploit", "Initial Access", "Execution", "Exfiltration", "Collection", "Credential Access", "Defense Evasion", "Discovery", "Impact"], missingval="N/A",tablefmt="html")
Rule_Creation_This_Year_Tabulated_HTML = tabulate.tabulate([Rules_Created_This_Year_Quarter, Rules_Created_This_Year_Group], headers = ["Q1", "Q2", "Q3", "Q4"], missingval="N/A", tablefmt="html")
Rule_Creation_Last_Year_Tabulated_HTML = tabulate.tabulate([Rules_Created_Last_Year_Quarter, Rules_Created_Last_Year_Group], headers = ["Q1", "Q2", "Q3", "Q4"], missingval="N/A", tablefmt="html")
Rules_Last_Updated_Tabulated_HTML = tabulate.tabulate([Rules_Last_Updated_Count, Rules_Last_Updated_Group], headers = ["more than 365 days", "between 365 and 180 days", "between 180 and 90 days", "less than 90 days"], missingval="N/A", tablefmt="html")

# Formatting these to simply print them to screen for debug purposes. 

Enabled_Rules_Tabulated_Grid = tabulate.tabulate([Enabled_Rules, Enabled_Rules_By_Tactic], headers = ["Command and Control", "Lateral Movement", "Malware", "Persistence", "Privilege Escalation", "Ransomware", "Suspicious Activity", "Unwanted Software", "Exploit", "Initial Access", "Execution", "Exfiltration", "Collection", "Credential Access", "Defense Evasion", "Discovery", "Impact"], missingval="N/A", tablefmt="simple")
Disabled_Rules_Tabulated_Grid = tabulate.tabulate([Disabled_Rules, Disabled_Rules_By_Tactic], headers = ["Command and Control", "Lateral Movement", "Malware", "Persistence", "Privilege Escalation", "Ransomware", "Suspicious Activity", "Unwanted Software", "Exploit", "Initial Access", "Execution", "Exfiltration", "Collection", "Credential Access", "Defense Evasion", "Discovery", "Impact"], missingval="N/A", tablefmt="simple")
Rule_Creation_This_Year_Tabulated_Grid = tabulate.tabulate([Rules_Created_This_Year_Quarter, Rules_Created_This_Year_Group], headers = ["Q1", "Q2", "Q3", "Q4"], missingval="N/A", tablefmt="simple")
Rule_Creation_Last_Year_Tabulated_Grid = tabulate.tabulate([Rules_Created_Last_Year_Quarter, Rules_Created_Last_Year_Group], headers = ["Q1", "Q2", "Q3", "Q4"], missingval="N/A", tablefmt="simple")
Rules_Last_Updated_Tabulated_Grid = tabulate.tabulate([Rules_Last_Updated_Count, Rules_Last_Updated_Group], headers = ["more than 365 days", "between 365 and 180 days", "between 180 and 90 days", "less than 90 days"], missingval="N/A", tablefmt="simple")

def Print_Tabulate_Debug():
    # Optional, this is just to print it to the terminal, just in case the user wants to read it in a different format. 
    # Also, it could be useful to have a showindex="always" setup for it, in case you want to add this to a DB or calculate some records.
    print(Enabled_Rules_Tabulated_Grid)
    print(Disabled_Rules_Tabulated_Grid)
    print(Rule_Creation_This_Year_Tabulated_Grid)
    print(Rule_Creation_Last_Year_Tabulated_Grid)
    print(Rules_Last_Updated_Tabulated_Grid)

Build_HTML()

# Debug 
# Print_Tabulate_Debug()
print("Check the file: " + filedatestr + " AllRulesQueryText.txt for all the queries.")
print("Check the file: " + filedatestr + " EnabledRulesQueryText.txt for all the enabled queries.")
print("Check the file: " + filedatestr + " DisabledRulesQueryText.txt for all the disabled queries.")
print("Those files should be a valid .KQL script, in case they are not, check if the input is valid. Raise me an issue over GitHub if you can't find a solution :)")

