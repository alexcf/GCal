# GCal
Retrieves data from multiple Google Calendars and updates Domoticz based on the events.

Wiki with installation instructions: https://github.com/allan-gam/GCal/wiki

GCal is written in Python and runs on Raspberry Pi. It can run on the same hardware as Domoticz or on different host as long as it can acess the Domoticz hosts API/JSON URL's.

GCal runs separate from Domoticz so it won't introduce any delays in the Domoticz event queue while waiting for external Google servers.
