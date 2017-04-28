#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# https://github.com/allan-gam/GCal
#
# This software has been designed to work with Google Calendar API
# It's aimed for Domoticz running on Raspberry Pi
# Copyright © 2017 Michael R. Stanton. michael.r.stanton1@gmail.com
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS`` AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import json
import io
import os
import plistlib
import requests
from urllib import urlencode
import sys, getopt
import datetime
import time
import logging
import httplib2
from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage
from oauth2client.client import OAuth2WebServerFlow
from dateutil import parser
import pytz

# Global (module) namespace variables
#redirect_uri = "http://showquerystring.000webhostapp.com/index.php" # Don't alter this or anything else!
cfgFile = sys.path[0] + '/.data/config.json'
configChanged = False
newDevicesList = [] # This is a python list
APPLICATION_NAME = 'Google Calendar API for Domoticz'

SCOPES = 'https://www.googleapis.com/auth/calendar.readonly'
VERSION = '0.0.3'
MSG_ERROR = 'Error'
MSG_INFO = 'Info'
MSG_EXEC = 'Exec info'
CAL_NO_FUTURE_EVENTS = 'No future events found'
tty = True if os.isatty(sys.stdin.fileno()) else False
isDebug = False
isVerbose = False
lastCredentials = None
lastClientID = ''
lastClientSecret = ''
dateStrFmt = '%Y-%m-%d %H:%M:%S'
gCaldateStrFmt = '%Y-%m-%dT%H:%M:%S'


def query_yes_no(question, default="no"):
	valid = {"yes": True, "y": True, "ye": True,
					 "no": False, "n": False}
	if default is None:
		prompt = " [y/n] "
	elif default == "yes":
		prompt = " [Y/n] "
	elif default == "no":
		prompt = " [y/N] "
	else:
		raise ValueError("invalid default answer: '%s'" % default)

	while True:
		sys.stdout.write(question + prompt)
		choice = raw_input().lower()
		if default is not None and choice == '':
			return valid[default]
		elif choice in valid:
			return valid[choice]
		else:
			sys.stdout.write("Please respond with 'yes' or 'no' "
														 "(or 'y' or 'n').\n")

def connected_to_internet(url='http://www.google.com/', timeout=5):
	try:
		_ = requests.head(url, timeout=timeout)
		return True
	except requests.ConnectionError:
		print('No internet connection available.')
	return False

def default_input(message, defaultVal):
	if defaultVal:
		return raw_input( "%s [%s]:" % (message, defaultVal) ) or defaultVal
	else:
		return raw_input( "%s :" % (message) )

def saveConfigFile():
	global configChanged
	with io.open(cfgFile, 'w', encoding='utf-8') as outfile:
		my_json_str = json.dumps(cfg, ensure_ascii=False, indent=2, sort_keys=True)
		if isinstance(my_json_str, str): # Python 2.x JSON module gives either Unicode or str depending on the contents of the object.
			my_json_str = my_json_str.decode('utf-8')
		outfile.write(my_json_str)
		configChanged = False

def create_config():
	global cfg;cfg = {}
	global configChanged

	data_dir = os.path.join(sys.path[0], '.data')
	if not os.path.exists(data_dir):
		os.makedirs(data_dir)

	import socket
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 0))	# connecting to a UDP address doesn't send packets
	local_ip_address = s.getsockname()[0]
	cfg['domoticz'] = {}

	cfg['domoticz']['timeZone'] = ''
	while not cfg['domoticz']['timeZone'] in pytz.all_timezones:
		cfg['domoticz']['timeZone'] = default_input('Domoticz Time Zone', 'Europe/Stockholm')
		if not cfg['domoticz']['timeZone'] in pytz.all_timezones:
			default_input('That isn\'t a valid time zone! Press any key to see a list of all valid zones', '')
			for tz in pytz.all_timezones:
				print tz
	cfg['domoticz']['hostName'] = default_input('Domoticz web interface IP address (or host name)', local_ip_address)
	cfg['domoticz']['portNumber'] = default_input('Domoticz web interface port number', 8080)
	cfg['domoticz']['protocol'] = ''
	while cfg['domoticz']['protocol'] <> 'http' and cfg['domoticz']['protocol'] <> 'https':
		cfg['domoticz']['protocol'] = default_input('Domoticz web interface communication protocol (http or https)', 'http')
		if cfg['domoticz']['protocol'] <> 'http' and cfg['domoticz']['protocol'] <> 'https':
			print 'Invalid value given for Domoticz web interface communication protocol. It must be \'http\' or \'https\''
	cfg['domoticz']['httpBasicAuth'] = {}
	cfg['domoticz']['httpBasicAuth']['userName'] = \
					default_input('Domoticz web interface user name (leave blank if no username is needed)', '')
	cfg['domoticz']['httpBasicAuth']['passWord'] = \
					default_input('Domoticz web interface password (leave blank if no passord is needed)', '')
	cfg['domoticz']['scpHost'] = \
					default_input('Send calendar data with SCP to username@host (leave blank if domoticz is installed on this machine)', '')
	cfg['domoticz']['scpDir'] = \
					default_input('Send calendar data with SCP to remote directory (leave blank if domoticz is installed on this machine)', '')
	cfg['calendars'] = {}
	cfg['calendars']['calendar'] = []

	cfg['system'] = {}
	tmpdir = '/var/tmp' if os.path.isdir('/var/tmp') else '/tmp'
	cfg['system']['tmpFolder'] = '/xxxx/yyyy'
	while not os.path.isdir(cfg['system']['tmpFolder']):
		cfg['system']['tmpFolder'] = default_input('Directory for app logging and storing access tokens', tmpdir)
		if not os.path.isdir(cfg['system']['tmpFolder']):
			print 'That isn\'t a valid directory name on Your system! Please try again.'
	# Do we already have a hardware device named 'Google Calendar' in Domoticz?
	payload = dict([('type', 'hardware')])
	r = domoticzAPI(payload)
	hwIdx = '0'
	HWNAME = 'Google Calendar'
	if 'result' in r.keys():
		for hw in r['result']:
			if hw['Name'] == HWNAME and hw['Enabled'] == 'true':
				hwIdx = hw['idx']
				break
	if hwIdx <> '0':
		cfg['domoticz']['virtualHwDeviceIdx'] = int(hwIdx)
	else:
		# Create a new Hardware Device. We wants it, we needs it. Must have the precious. They stole it from us!
		payload = dict([('type', 'command'), ('param', 'addhardware'), ('htype', 15), \
										('port', 1), ('name', HWNAME), ('enabled', 'true'), ('datatimeout', 0)])
		r = domoticzAPI(payload)
		# Now go fishing for the hardware device Idx
		payload = dict([('type', 'hardware')])
		r = domoticzAPI(payload)
		for hw in r['result']:
			if hw['Name'] == HWNAME and hw['Enabled'] == 'true':
				hwIdx = hw['idx']
				break
		if hwIdx <> '0':
			cfg['domoticz']['virtualHwDeviceIdx'] = int(hwIdx)
		else:
			print 'Can not find the newly created virtual hardware device.'
			sys.exit(0)

	# ROOM PLAN
	# Do we already have a room plane named 'Google Calendars' in Domoticz?
	payload = dict([('type', 'plans')])
	r = domoticzAPI(payload)
	roomIdx = '0'
	ROOMPLAN = 'Google Calendars'
	if 'result' in r.keys(): # Can happen if there are no room plans
		for room in r['result']:
			if room['Name'] == ROOMPLAN:
				roomIdx = room['idx']
				break
	if roomIdx <> '0':
		cfg['domoticz']['roomPlan'] = int(roomIdx)
	else:
		# Create a new Room Plan
		payload = dict([('type', 'command'), ('param', 'addplan'), ('name', ROOMPLAN)])
		r = domoticzAPI(payload)
		# Now go fishing for the room plan Idx
		payload = dict([('type', 'plans')])
		r = domoticzAPI(payload)
		for room in r['result']:
			if room['Name'] == ROOMPLAN:
				roomIdx = room['idx']
				break
		if roomIdx <> '0':
			cfg['domoticz']['roomPlan'] = int(roomIdx)
		else:
			print 'Can not find the newly created room plan.'
			sys.exit(0)
	saveConfigFile()
	return cfg

def load_config():
	try:
		with open(cfgFile) as json_data_file:
			cfg = json.load(json_data_file)
	except IOError:
		# Create a new config file
		if tty:
			cfg = create_config()
		else:
			logMessage = 'Can not open the config file ' + cfgFile
			logToDomoticz(MSG_ERROR, logMessage)
			sys.exit(0)
	except:
		logMessage = 'Can not open the config file ' + cfgFile
		if tty: print logMessage, sys.exc_info()[0]
		sys.exit(0)
	return cfg

def domoticzAPI(payload):
	try:
		r = requests.get(cfg['domoticz']['protocol'] + '://' + cfg['domoticz']['hostName'] + ':' + \
										 str(cfg['domoticz']['portNumber']) + '/json.htm', \
										 auth=(cfg['domoticz']['httpBasicAuth']['userName'], cfg['domoticz']['httpBasicAuth']['passWord']), \
										 params=payload)
	except:
		if tty: print('Can not open domoticz URL: \'' + cfg['domoticz']['protocol'] + '://' + cfg['domoticz']['hostName'] + ':' + \
										 str(cfg['domoticz']['portNumber']) + '/json.htm\'', sys.exc_info()[0])
		sys.exit(0)
	if r.status_code <> 200:
		if tty: print 'Unexpected status code from Domoticz: ' + r.status_code
		sys.exit(0)
	try:
		rJsonDecoded = r.json()
	except:
		if tty: print('Can\'t Json decode response from Domoticz.', sys.exc_info()[0])
		sys.exit(0)
	if rJsonDecoded['status'] <> 'OK':
		if tty: print 'Unexpected response from Domoticz: ' + rJsonDecoded['status']
		sys.exit(0)
	return rJsonDecoded

def logToDomoticz(messageType, logMessage):
	payload = dict([('type', 'command'), ('param', 'addlogmessage'), \
								('message', '(' + messageType+ ') ' + os.path.basename(sys.argv[0]) + ': ' + logMessage)])
	r = domoticzAPI(payload)
	return r

def createConfigEntry():

	entry = {}
	if not tty:
		return entry
	lastOAuth2ClientID = ''
	lastOAuth2ClientSecret = ''
	if len (cfg['calendars']['calendar']) > 0:
		lastOAuth2ClientID = cfg['calendars']['calendar'][0]['oAuth2ClientCredentials']['clientId']
		lastOAuth2ClientSecret = cfg['calendars']['calendar'][0]['oAuth2ClientCredentials']['clientId']
	entry['enabled'] = False

	entry['tripped'] = False # Set by the device. 0 if not tripped, 1 if tripped
	entry['trippedEvent'] = None # Set by the device. The name of the currently tripped event (if tripped) or the next event (if not tripped)
	entry['eventsToday'] = 0 # Set by the device. Gives a count of the number of events present in the calendar in the current (local time) 24 hrs. This will remain the same during the day.
	entry['remainingEventsToday'] = 0 # Set by the device. Gives a count of the number of events remaining in the current day. This will start out equal to eventsToday and decrease as each event completes. When no more events remain it will be 0
	entry['lastCheck'] =  (datetime.datetime.now() - datetime.timedelta(days=10)).strftime(dateStrFmt) # Set by the device. The date and time the script last checked the calendar

	entry['domoticzSwitchIdx'] = 0
	entry['domoticzTextIdx'] = 0

	entry['shortName'] = ''
	while len(entry['shortName']) < 1:
		entry['shortName'] = default_input('Calendar short name (Any unique name that You wish to use for this calendar) ', '')
		if len(entry['shortName']) < 1:
			print 'That doesn\'t look like a valid short name'
			print 'Please try again'

	entry['oAuth2ClientCredentials'] = {}

	match = None
	entry['calendarAddress'] = ''
	while (match == None):
		entry['calendarAddress'] = default_input('Calendar public address (in form of an email address)', '')
		import re
		match = re.match('^[_a-z0-9-\#]+(\.[_a-z0-9-\#]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', entry['calendarAddress'])
		if (match == None):
			print '\'' + entry['calendarAddress'] + '\' doesn\'t look like a valid calendar public address'
			print 'Please try again'

	entry['oAuth2ClientCredentials']['clientId'] = ''
	while len(entry['oAuth2ClientCredentials']['clientId']) < 10:
		entry['oAuth2ClientCredentials']['clientId'] = default_input('Calendar OAuth2 Client ID:', lastOAuth2ClientID)
		if len(entry['oAuth2ClientCredentials']['clientId']) < 10:
			print 'That doesn\'t look like a valid OAuth2 Client ID'
			print 'Please try again'

	entry['oAuth2ClientCredentials']['clientSecret'] = ''
	while len(entry['oAuth2ClientCredentials']['clientSecret']) < 10:
		entry['oAuth2ClientCredentials']['clientSecret'] = default_input('Calendar OAuth2 Client Secret', lastOAuth2ClientSecret)
		if len(entry['oAuth2ClientCredentials']['clientSecret']) < 10:
			print 'That doesn\'t look like a valid OAuth2 Client Secret'
			print 'Please try again'

	# This is the maximum amount of time in minutes between refreshes of the calendar.
	entry['interval'] = 0
	while entry['interval'] < 5 or entry['interval'] > 60*24:
		entry['interval'] = default_input('Number of minutes between refreshes of the calendar (5-10080)', '180')
		try:
			entry['interval'] = int(entry['interval'])
		except ValueError:
			entry['interval'] = 0
			pass
		if entry['interval'] < 5 or entry['interval'] > 60*24*7:
			print 'That doesn\'t look like a valid value'
			print 'Please try again'

	# This is the number of minutes before (negative) or after the event start time that you want the script to turn on. Applies to all events unless an event specific start/end delta is defined
	entry['startDelta'] = -999999
	while entry['startDelta'] < -1440 or entry['startDelta'] > 1440:
		entry['startDelta'] = default_input('Number of minutes before (negative) or after the event start time that you want the device to turn on. (-1440 to 1440)', '0')
		try:
			entry['startDelta'] = int(entry['startDelta'])
		except ValueError:
			entry['startDelta'] = -999999
			pass
		if entry['startDelta'] < -1440 or entry['startDelta'] > 1440:
			print 'That doesn\'t look like a valid value'
			print 'Please try again'

	# This is the number of minutes before (negative) or after the event start time that you want the script to turn off. Applies to all events unless an event specific start/end delta is defined
	entry['endDelta'] = -999999
	while entry['endDelta'] < -1440 or entry['endDelta'] > 1440:
		entry['endDelta'] = default_input('Number of minutes before (negative) or after the event start time that you want the device to turn off. (-1440 to 1440)', '0')
		try:
			entry['endDelta'] = int(entry['endDelta'])
		except ValueError:
			entry['endDelta'] = -999999
			pass
		if entry['endDelta'] < -1440 or entry['endDelta'] > 1440:
			print 'That doesn\'t look like a valid value'
			print 'Please try again'

	# If set this specifies the event name and / or description to match. the script will force it to upper case. The behavior depends on the values set for gc_exactKeyword and gc_ignoreKeyword. Can be left blank or can be a keyword or phrase. Multiple keywords can be specified if separated by a semi-colon ;
	entry['keyword'] = default_input('Keyword. Event name and / or description to match. (Can be left blank or can be a keyword or phrase. Multiple keywords can be specified if separated by a semi-colon. If left blank, the script will trigger on every event.) ', '')

	# Set this to true if you want the script to match an event name exactly. Set to false if you want the script to match anywhere in the event name.
	entry['exactKeyword'] = False
	if entry['keyword'] != '':
		if query_yes_no('Match an event name exactly', 'yes'):
			entry['exactKeyword'] = True

	# Set this to true if you want the script to ignore any events where the event name matches the keyword or the description contains the keyword. Default is false.
	entry['ignoreKeyword'] = False
	if entry['keyword'] != '':
		if query_yes_no('Ignore any events where the event name matches the keyword or the description contains the keyword', 'no'):
			entry['ignoreKeyword'] = True

	# Set this to true if you want the script to ignore all day events. Default is false.
	entry['ignoreAllDayEvent'] = False
	if query_yes_no('Ignore all day events', 'no'):
		entry['ignoreAllDayEvent'] = True

	# Set this to false so that back-to-back events with the same name will be treated as one long event. Useful for repeating all-day events. Default is true.
	entry['retrip'] = False
	if query_yes_no('Treat back-to-back events with the same name as one long event', 'yes'):
		entry['retrip'] = True

	domoSwitchDeviceName = 'GCal ' + entry['shortName']
	domoTextDeviceName = 'GCal Status ' + entry['shortName']
	if entry['startDelta'] != 0 or entry['endDelta'] != 0:
		domoSwitchDeviceName = domoSwitchDeviceName + ' ('  + str(entry['startDelta']) + ':' + str(entry['endDelta']) + ')'
		domoTextDeviceName = domoTextDeviceName + ' ('  + str(entry['startDelta']) + ':' + str(entry['endDelta']) + ')'

	# Create a Virtual Switch Device
	domoticzSensorType = 6 # Switch
	payload = dict([('type', 'createvirtualsensor'), ('idx', cfg['domoticz']['virtualHwDeviceIdx']), \
								('sensorname', domoSwitchDeviceName), ('sensortype', domoticzSensorType)])
	r = domoticzAPI(payload)
	# Now go fishing for the newly created device idx
	payload = dict([('type', 'devices')])
	r = domoticzAPI(payload)
	devIdx = 0
	for dev in reversed(r['result']):
		if dev['Name'] == domoSwitchDeviceName and dev['HardwareID'] == cfg['domoticz']['virtualHwDeviceIdx'] and dev['SubType'] == 'Switch':
			devIdx = dev['idx']
			break
	if devIdx <> '0':
		entry['domoticzSwitchIdx'] = int(devIdx)
		entry['enabled'] = True
		print 'Created Domoticz virtual switch device (idx) : ' + str(devIdx)
	else:
		print 'Error: Can not find the newly created virtual switch device.'
		sys.exit(0)
	# Add the device to the Domoticz room plan
	payload = dict([('type', 'command'), ('param', 'addplanactivedevice'), ('idx', cfg['domoticz']['roomPlan']), \
									('activetype', 0), ('activeidx', devIdx)])
	r = domoticzAPI(payload)

	# Create a Virtual Text Device
	domoticzSensorType = 5 # Text Device
	payload = dict([('type', 'createvirtualsensor'), ('idx', cfg['domoticz']['virtualHwDeviceIdx']), \
								('sensorname', domoTextDeviceName), ('sensortype', domoticzSensorType)])
	r = domoticzAPI(payload)
	# Now go fishing for the newly created device idx
	payload = dict([('type', 'devices')])
	r = domoticzAPI(payload)
	devIdx = 0
	for dev in reversed(r['result']):
		if dev['Name'] == domoTextDeviceName and dev['HardwareID'] == cfg['domoticz']['virtualHwDeviceIdx'] and dev['SubType'] == 'Text':
			devIdx = dev['idx']
			break
	if devIdx <> '0':
		entry['domoticzTextIdx'] = int(devIdx)
		entry['enabled'] = True
		print 'Created Domoticz virtual switch device (idx) : ' + str(devIdx)
	else:
		print 'Error: Can not find the newly created virtual switch device.'
		sys.exit(0)
	# Add the device to the Domoticz room plan
	payload = dict([('type', 'command'), ('param', 'addplanactivedevice'), ('idx', cfg['domoticz']['roomPlan']), \
									('activetype', 0), ('activeidx', devIdx)])
	r = domoticzAPI(payload)

	updateDomoTextDevice(entry) # Update the text on the text device

	cfg['calendars']['calendar'].append(entry)
	with open(cfgFile, 'w') as outfile:
		json.dump(cfg, outfile, indent=2, sort_keys=True, separators=(',', ':'))
	configChanged = False

	return entry

def updateDomoSwitchDevice(calendarEntry):
	if not calendarEntry['enabled']:
		return
	# Only update if the new value differs from the device value
	# or if the device has not been updated for a while
	payload = dict([('type', 'devices'), ('rid', calendarEntry['domoticzSwitchIdx'])])
	r = domoticzAPI(payload)

	if not 'result' in r.keys():
		errMess = 'Failure getting data for domoticz device idx: ' + str(calendarEntry['domoticzSwitchIdx'])
		print errMess
		logToDomoticz(MSG_ERROR, errMess)
		return

	domoCompareValue = r['result'][0]['Status']
	if calendarEntry['tripped']:
		newValue = 'On'
	else:
		newValue = 'Off'

	valueChanged = False
	if newValue <> domoCompareValue: valueChanged = True

	if isDebug:
		print r['result'][0]['Name']
		print 'N: ' + newValue
		print 'D: ' + str(domoCompareValue)
		print
	elif isVerbose and valueChanged:
		sayThis = 'Updating Domoticz device \'' + r['result'][0]['Name'] + '\' idx: ' + str(calendarEntry['domoticzSwitchIdx']) + ' due to:'
		if valueChanged: sayThis += ' <value changed>. New value is: ' + newValue + \
																'. Old value was: ' + str(domoCompareValue) + '.'
		print sayThis

	if not valueChanged:
		return

	payload = dict([('type', 'command'), ('param', 'switchlight'), ('idx', calendarEntry['domoticzSwitchIdx']), \
								('switchcmd', newValue)])
	r = domoticzAPI(payload)

def updateDomoTextDevice(calendarEntry):
	if not calendarEntry['enabled']:
		return
	# Only update if the new value differs from the device value
	# or if the device has not been updated for a while
	payload = dict([('type', 'devices'), ('rid', calendarEntry['domoticzTextIdx'])])
	r = domoticzAPI(payload)

	if not 'result' in r.keys():
		errMess = 'Failure getting data for domoticz device idx: ' + str(calendarEntry['domoticzTextIdx'])
		if tty: print errMess
		logToDomoticz(MSG_ERROR, errMess)
		return

	domoCompareValue = r['result'][0]['Data']
	if calendarEntry['trippedEvent'] == None:
		newValue = CAL_NO_FUTURE_EVENTS
	else:
		newValue = calendarEntry['trippedEvent']

	valueChanged = False
	if newValue <> domoCompareValue: valueChanged = True
	if isDebug:
		print r['result'][0]['Name']
		print 'N: ' + newValue
		print 'D: ' + domoCompareValue
		print
	elif isVerbose and valueChanged:
		sayThis = 'Updating Domoticz device \'' + r['result'][0]['Name'] + '\' idx: ' + str(calendarEntry['domoticzTextIdx']) + ' due to:'
		if valueChanged: sayThis += ' <value changed>. New value is: ' + newValue + \
																'. Old value was: ' + domoCompareValue + '.'
		print sayThis

	if not valueChanged:
		return

	payload = dict([('type', 'command'), ('param', 'udevice'), ('idx', calendarEntry['domoticzTextIdx']), \
								('svalue', newValue)])
	r = domoticzAPI(payload)

def get_credentials(c, cred_args):
	"""Gets valid user credentials from storage.

	If nothing has been stored, or if the stored credentials are invalid,
	the OAuth2 flow is completed to obtain the new credentials.

	Returns:
		Credentials, the obtained credential.
	"""
	global lastCredentials
	global lastClientID

	client_id = c['oAuth2ClientCredentials']['clientId']
	if client_id == lastClientID:
		# Re-using last credentials
		return lastCredentials

	flags = tools.argparser.parse_args(args=cred_args)

	credential_dir = os.path.join(sys.path[0], '.credentials')
	if not os.path.exists(credential_dir):
		os.makedirs(credential_dir)
	credential_path = os.path.join(credential_dir, client_id + '.json')

	store = Storage(credential_path)
	credentials = store.get()
	if not credentials or credentials.invalid:
		flow = OAuth2WebServerFlow(client_id=client_id,
						client_secret=c['oAuth2ClientCredentials']['clientSecret'],
						scope=SCOPES,
						redirect_uri='http://localhost:8080')
		flow.user_agent = APPLICATION_NAME
		credentials = tools.run_flow(flow, store, flags)

		logMessage = 'Storing credentials to ' + credential_path
		logToDomoticz(MSG_INFO, logMessage)
		if isVerbose: print logMessage

	lastCredentials = credentials
	lastClientID = client_id

	return credentials

def syncWithGoogle(c):
	global cfg
	cred_args = []
	cred_args.append('--noauth_local_webserver')

	timeMin = (datetime.datetime.utcnow() + datetime.timedelta(minutes=c['endDelta']) - datetime.timedelta(hours=24)) # Limit for historical events
	timeMax = (datetime.datetime.utcnow() + datetime.timedelta(minutes=c['startDelta']) + datetime.timedelta(hours=24)) # Limit for future events
	timeMax = timeMax + datetime.timedelta(minutes=c['interval']) # Add the update interval to timeMax
	timeMin = timeMin.isoformat() + 'Z'
	timeMax = timeMax.isoformat() + 'Z'

	credentials = get_credentials(c, cred_args)
	http = credentials.authorize(httplib2.Http())
	service = discovery.build('calendar', 'v3', http=http)

	logMessage = 'Getting events for calendar ' + c['calendarAddress']
	logToDomoticz(MSG_INFO, logMessage)
	if isVerbose: print logMessage

	eventsResult = service.events().list(
		calendarId=c['calendarAddress'], timeMin=timeMin, timeMax=timeMax, singleEvents=True,
		orderBy='startTime').execute()
	events = eventsResult.get('items', [])

	if not events:
		if tty: print('No events found.')
	for event in events:
		start = event['start'].get('dateTime', event['start'].get('date'))
		if tty: print(start, event['summary'])

	data_dir = os.path.join(cfg['system']['tmpFolder'], 'GCalData')
	if not os.path.exists(data_dir):
		os.makedirs(data_dir)
	data_path = os.path.join(data_dir, str(c['calendarAddress']) + '.json')

	with io.open(data_path, 'w', encoding='utf-8') as outfile:
		my_json_str = json.dumps(events, ensure_ascii=False, indent=2, sort_keys=True)
		if isinstance(my_json_str, str): # Python 2.x JSON module gives either Unicode or str depending on the contents of the object.
			my_json_str = my_json_str.decode('utf-8')
		outfile.write(my_json_str)

	# Copy the calendar json data to remote host if applicable
	# SSH public-key authentication to connect to a remote system must have been established prior to using
	if len(cfg['domoticz']['scpHost']) > 0 and len(cfg['domoticz']['scpDir']) > 0:
		from subprocess import call
		cmd = 'ssh ' + cfg['domoticz']['scpHost'] + ' mkdir -p ' + cfg['domoticz']['scpDir']
		call(cmd.split(" "))
		cmd = 'scp ' + data_path + ' ' + cfg['domoticz']['scpHost'] + ':' + cfg['domoticz']['scpDir']
		if isVerbose: print cmd
		call(cmd.split(" "))

def load_calendar(c):
	data_dir = os.path.join(cfg['system']['tmpFolder'], 'GCalData')
	data_path = os.path.join(data_dir, str(c['calendarAddress']) + '.json')
	try:
		with open(data_path) as json_calendar_file:
			events = json.load(json_calendar_file)
	except:
		logMessage = 'Can not open the calendar file ' + data_path
		if tty: print logMessage, sys.exc_info()[0]
		sys.exit(0)
	return events

def process_calendar(c):
	global cfg
	global configChanged

	events = load_calendar(c)
	# Get the current UTC offset
	offset = (time.timezone if (time.localtime().tm_isdst == 0) else time.altzone) / 60 / 60 * -1

	utcTime = datetime.datetime.utcnow()
	tz = pytz.timezone(cfg['domoticz']['timeZone'])
	utcTime = utcTime.replace(tzinfo=pytz.UTC) #replace method, convert the naive object into a zone aware object
	domoticzNow= utcTime.astimezone(tz)

	eventsToday = 0
	remainingEventsToday = 0
	tripped = False
	trippedEvent = None

	activeEvent = CAL_NO_FUTURE_EVENTS
	withinEvent = False
	format1 = ''
	format2 = ''
	eventTimeText = ''

	for e in events:
		if 'date' in e['start'] and not c['ignoreAllDayEvent'] : # An all day event found
			startDateTime = parser.parse(e['start']['date']+'T00:00:00' + '{:+d}'.format(offset))
			endDateTime = parser.parse(e['end']['date']+'T00:00:00' + '{:+d}'.format(offset))
		elif 'dateTime' in e['start']:
			startDateTime = parser.parse(e['start']['dateTime'])
			endDateTime = parser.parse(e['end']['dateTime'])

		# Deal with keyword filtering
		if c['keyword'] != '':
			#print 'Keywords in use: ' + c['keyword']
			keyWordFound = False
			keyWords = c['keyword'].lower().split(';')
			for keyWord in keyWords:
				if not keyWordFound: keyWordFound = e['summary'].lower().find(keyWord) > 0
				if not keyWordFound: keyWordFound = e['description'].lower().find(keyWord) > 0
				#if keyWordFound: print(keyWord)

			if (c['ignoreKeyword'] and keyWordFound) \
			or (not c['ignoreKeyword'] and not keyWordFound):
				print 'rejects all the remaining statements for event: ' + e['summary']
				continue # rejects all the remaining statements for this event

		# Deal with calendar time offsets
		startDateTime = startDateTime + datetime.timedelta(minutes=c['startDelta'])
		endDateTime = endDateTime + datetime.timedelta(minutes=c['endDelta'])

		# Subtract 1 minute from endDateTime so that it will hold the last minute that the event is considered active
		endDateTimeMinus1min = endDateTime - datetime.timedelta(seconds=60)

		if domoticzNow.date() == startDateTime.date() or domoticzNow.date() == endDateTimeMinus1min.date():
			eventsToday = eventsToday + 1
			if domoticzNow <= endDateTimeMinus1min:
				remainingEventsToday = remainingEventsToday + 1

		if trippedEvent == None:
			if startDateTime.hour == 0 and startDateTime.minute == 0 and endDateTime.hour == 0 and endDateTime.minute == 0:
				eventTimeText = startDateTime.strftime('%Y-%m-%d. (All day event)')
			else:
				eventTimeText = startDateTime.strftime('%Y-%m-%d. From %H:%M') + ' to ' + endDateTime.strftime('%H:%M')

			withinEvent = True if (domoticzNow >= startDateTime) and (domoticzNow <= endDateTimeMinus1min) else False
			if withinEvent:
				tripped = True
				trippedEvent = e['summary']
				# print trippedEvent # Causes serious error if running in background!!!! 
				# TODO: What if we have more active events? How should they be handled? Now we are only using the first event found that we are within
			elif (domoticzNow < startDateTime):
				trippedEvent = e['summary']

	#
	#                                ("`-''-/").___..--''"`-._ 
	#                                `6_ 6  )   `-.  (     ).`-.__.`) 
	#                                (_Y_.)'  ._   )  `._ `. ``-..-`  
	#                              _..`--'_..-_/  /--'_.' ,'  
	#                             (il),-''  (li),'  ((!.-'
	#

	seqText = ' !#' + str(remainingEventsToday) + '(' + str(eventsToday) + ')' + '!#'
	if trippedEvent == None:
		trippedEvent = CAL_NO_FUTURE_EVENTS
	if not tripped:
		format1 = '<span style="color: grey;">' # Future events are shown in grey
		format2 = '</span>'
	trippedEvent = format1 + trippedEvent + format2 + seqText + '<BR/><span style="font-weight: normal;">' + eventTimeText + '</span>'

	#if tripped:
	#eventsToday == remainingEventsToday:
	
	#if tripped:


	if eventsToday != c['eventsToday'] \
	or remainingEventsToday != c['remainingEventsToday'] \
	or tripped != c['tripped'] \
	or trippedEvent != c['trippedEvent']:
		configChanged = True
		c['eventsToday'] = eventsToday
		c['remainingEventsToday'] = remainingEventsToday
		c['tripped'] = tripped
		c['trippedEvent'] = trippedEvent
	updateDomoTextDevice(c)
	updateDomoSwitchDevice(c)

def list_calendars():
	global cfg
	global configChanged
	global createNewConfigEntry
	while (len(cfg['calendars']['calendar']) < 1) or createNewConfigEntry:
		createConfigEntry()
		if len(cfg['calendars']['calendar']) < 1:
			print 'That didn\'t seem to work.'
		else:
			createNewConfigEntry = False
			cfg = load_config()

	logMessage = 'Found a total of : ' + str(len(cfg['calendars']['calendar'])) + ' calendar configuration entries.\n'
	if isVerbose: logToDomoticz(MSG_INFO, logMessage)
	if isVerbose: print logMessage

	for c in cfg['calendars']['calendar']:
		if c['enabled']:
			elapsed = datetime.datetime.now() - datetime.datetime.strptime(c['lastCheck'], dateStrFmt)

			if elapsed.seconds/60 >= c['interval']:
				logMessage = 'Fetching Calendar : ' + c['shortName'] + '. Last fetched: ' + str(elapsed.seconds/60) + ' minutes ago. Interval: ' +str(c['interval'])
				logToDomoticz(MSG_INFO, logMessage)
				if tty: print logMessage
				syncWithGoogle(c)
				c['lastCheck'] = datetime.datetime.now().strftime(dateStrFmt)
				configChanged = True
			else:
				if isVerbose:
					logMessage = 'Skipping Calendar : ' + c['shortName'] + '. Last fetched: ' + str(elapsed.seconds/60) + ' minutes ago. Interval: ' +str(c['interval'])
					logToDomoticz(MSG_INFO, logMessage)
					print logMessage
			process_calendar(c)

	if configChanged:
		logMessage = 'Config changed... Needs to save'
		if tty: print logMessage
		if isVerbose: logToDomoticz(MSG_INFO, logMessage)
		saveConfigFile()

def print_help(argv):
	print 'usage: ' + os.path.basename(__file__) + ' [option] [-C domoticzDeviceidx|all] \nOptions and arguments'
	print '-d		 : debug output (also --debug)'
	print '-h		 : print this help message and exit (also --help)'
	print '-v		 : verbose'
	print '-V		 : print the version number and exit (also --version)'
	print '-c		 : create an additional GCal entry (also --create_gcal_entry)'

def main(argv):
	if os.geteuid() == 0:
		sys.exit('\nThis script should not be run as user \'root\'\n')
	global isDebug
	global isVerbose

	global createNewConfigEntry;createNewConfigEntry = False
	try:
		opts, args = getopt.getopt(argv, 'dhvVc', ['help', 'debug', 'version', 'create_gcal_entry'])
	except getopt.GetoptError:
		print_help(argv)
		sys.exit(2)
	for opt, arg in opts:
		if opt in ('-h', '--help'):
			print_help(argv)
			sys.exit(0)
		elif opt in ('-d', '--debug'):
			isDebug = True
		elif opt in ('-v'):
			isVerbose = True
		elif opt in ('-V', '--version'):
			print APPLICATION_NAME + ' ' + VERSION
			sys.exit(0)
		elif opt in ("-c", "--create_gcal_entry"):
			createNewConfigEntry = True

	if isDebug: print 'Debug is on'
	if not tty: time.sleep( 5 ) # Give Domoticz some time to settle down from other commands running exactly at the 00 sec
	global cfg; cfg = load_config()
	global logFile; logFile = os.path.join(cfg['system']['tmpFolder'], os.path.basename(sys.argv[0]) + '.log')

	if not connected_to_internet():
		logToDomoticz(MSG_ERROR, 'No internet connection available')
		sys.exit(0)

	msgProgInfo = APPLICATION_NAME + ' Version ' + VERSION
	msgProgInfo += ' running on TTY console...' if tty else ' running as a CRON job...'
	logToDomoticz(MSG_EXEC, msgProgInfo)
	if isVerbose: print msgProgInfo

	list_calendars()
	sys.exit(0)

if __name__ == '__main__':
	main(sys.argv[1:])
