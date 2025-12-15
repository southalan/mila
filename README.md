
# MILA 🍞🥩🍞
```
My Ill Lackers in Azure 
```

## Purpose

DrawerGraphicator.py -> This is a python script that leverages plotly and tabulate to give you a small graphical report of your Advanced Hunting rules. 

## How to use?

```
# Install the script dependencies
pip install -r /path/to/requirements.txt
# Validate that everything is okay with the "SampleInput.txt" (These are 3 randomly created rules)
python3 DrawerGraphicator.py SampleInput.txt
# The results will be 4 files.
# 3, are .txt files that are valid .KQL script files. They will be later used on a project that I'm developing, so stay tuned. If you are astute, you will notice that you can use them to have a small repository of your DetectionRules as displayName, Id, QueryText in a human readable format. Handy if you have >200 rules.  
# 1, is an .html files with graphics giving you some insights about your detections. 
```

## How do I test my own detections instead of the "test file"?

```
Go to https://developer.microsoft.com/en-us/graph/graph-explorer
Make sure you are:
1) Authenticated with your tenant
2) You have provided permissions (CustomDetection.Read.All) to GraphExplorer.
3) Do a GET request to: https://graph.microsoft.com/beta/security/rules/detectionRules
4) Copy the contents of the response to a file AS THEY COME, ex: "MyDetections.txt" to the folder where the script is residing. 
5) Run python3 DrawerGraphicator.py MyDetections.txt
```

## This is cool, but I need "x" or want to add "y", how do I request/contribute?

```
These are the current options: 
-> Raise me an issue describing your use case or situation, and I'll if I can develop it. 
-> Create the graphic that you want me to add, and I'll merge it with the codebase.
-> Report an issue as a bugfix, and I'll get right into it. 
```

## RoadMap

```
-> (DrawerGraphicator.py) Improve the args[] and give you more space for customization (Ex: Disable certain graphs, change certain units, etc)
-> (DrawerGraphicator.py) Get a better handle of unusual queries (Those that use \r \n or RegEx themselves, and parse them correctly) 
-> (Upcoming) .KQL automation so you can run your AH files for automated detection testing.
```

## Example, Figure 1

Comparison of Enabled/Disabled rule count

<img width="1887" height="913" alt="newplot(1)" src="https://github.com/user-attachments/assets/f860548d-54c5-4e38-984d-4e213dec301b" />

## Example, Figure 5

Rule creation per quarter, last 2 years.

<img width="1887" height="913" alt="newplot(4)" src="https://github.com/user-attachments/assets/1bfbdb00-2f8c-45d1-ac2e-b9236ffc5780" />
