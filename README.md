
# MILA 🍞🥩🍞
```
My Ill Lackers in Azure 
```

## Purpose

This is a python script that leverages plotly and tabulate to give you a small graphical report of your Advanced Hunting rules. 

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

