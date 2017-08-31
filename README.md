[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)


# GCal
Retrieves data from multiple Google Calendars and updates Domoticz based on the events.

Wiki with installation instructions: https://github.com/allan-gam/GCal/wiki

## Upgrading from a version lower than 0.2.0? Please read this first!
Due to that the config files structure have changed, you will need to do the following first.
1. Rename the config.json file in /home/pi/GCal/.data to xconfig.json
2. Delete all the GCal Switch devices and all the GCal Text devices in Domoticz
3. Update GCal to the latest version, `cd ~/GCal&&git pull`
4. Run `/usr/bin/python /home/pi/GCal/gcal.py` again

GCal is written in Python and runs on Raspberry Pi. It can run on the same hardware as Domoticz or on different host as long as it can acess the Domoticz hosts API/JSON URL's.

Please note that this version of the program is still in its beta stage and for those of you who do decide to install the software we will appreciate your kind help to sort out any bugs which may appear.

GCal runs separate from Domoticz so it won't introduce any delays in the Domoticz event queue while waiting for external Google servers.
