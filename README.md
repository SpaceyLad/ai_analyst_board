# ai_analyst_board
A board of agents working together to analyze event log files.

# Version 0.1
This is still an early prototype. It is very token hungry and does a decent job at pointing out anomalies in the logs. You can use it, but be mindful of this.

## Disclaimer
- Do not upload sensitive data.
- Token use is high at the moment! Be careful not to have to large log files to ingest.
- Tested with Application and Sysmon logs.

## How to use
1. Install the required libraries. required.txt will come later in development.
2. Convert the logs to XML in event viewer.
3. Place the logs.xml in the same folder as this program
4. Add your API token in the config.
5. Run! :D

Tips:
Take a glance at the amount of entries it detects. If it is over 3000, it might crash because of the amount of data.
This will be fixed in future update.

## Future goal
- Fewer false positives.
- Less token use. Remove all unnecessary data.
- Support other filetypes than XML.
- Support large logs. (Split them into smaller tasks for the agents to analyze/digest)

### Test logs
Test logs are taken from the Huntress CTF Hard task [Chainsaw Massacre]. It is to see if it managed to spot the malicious payload.
So far it is able to do it! But with a handful of false positives.