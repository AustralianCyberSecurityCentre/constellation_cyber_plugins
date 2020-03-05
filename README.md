# ACSC Cyber Tools

The ACSC CyberTools Plugins are build upon the functionality of the Constellation data visualisation platform (https://www.constellation-app.com/).

# Enrichments
The enrichments that are available in these plugins are:
##### 1. Maxmind (https://maxmind.com)
  This geolocation service for IP addresses can be used in either a network or standalone mode.  
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > Maxmind tab.
  To use in network mode, add in your Maxmind User Id and API key, to use is standalone mode, download the mmdb files from Maxmind and set the locations.  
  
##### 2. VirusTotal (https://virustotal.com)
  This plugin will return any details found in VirusTotal for the selected Hashes.
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > VirusTotal tab, set your API Key here.

# Setup
These plugins are dependant on the constellation core repository (https://github.com/constellation-app/constellation).  Please clone this repository first and make sure that you add the cloned location to the ACSCCyberTools project properties.
This can be done by right clicking the module suite "ACSCCyberTools" and selecting Properties option, then choose Libraries and press the "Add Cluster" button.
