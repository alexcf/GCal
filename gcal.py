#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# https://github.com/allan-gam/GCal
#
# allan-gam/GCal is licensed under the GNU General Public License v3.0

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
googleCalStatesChanged = False
gcalStatesChanged = False
newDevicesList = [] # This is a python list
APPLICATION_NAME = 'Google Calendar API for Domoticz'

SCOPES = 'https://www.googleapis.com/auth/calendar.readonly'
VERSION = '0.3.1'
DB_VERSION = '1.0.1'
MSG_ERROR = 'Error'
MSG_INFO = 'Info'
MSG_EXEC = 'Exec info'
CAL_NO_FUTURE_EVENTS = 'No future events found'
tty = True if os.isatty(sys.stdin.fileno()) else False
isDebug = False
isVerbose = False
reConfigure = False
lastCredentials = None
lastClientID = ''
lastClientSecret = ''
dateStrFmt = '%Y-%m-%d %H:%M:%S'
gCaldateStrFmt = '%Y-%m-%dT%H:%M:%S'
TEXT_DEV_NO_EVENT = 'No event'

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

# get a UUID - URL safe, Base64
def get_a_uuid():
	import base64
	import uuid
	r_uuid = base64.urlsafe_b64encode(uuid.uuid4().bytes)
	return r_uuid.replace('=', '')

def connected_to_internet(url='http://www.google.com/', timeout=5):
	try:
		_ = requests.head(url, timeout=timeout)
		return True
	except requests.ConnectionError:
		print('No internet connection available.')
	return False

def default_input(message, defaultVal):
	if defaultVal:
		answer = raw_input("%s [%s]:" % (message, defaultVal)) or defaultVal
	else:
		answer = raw_input("%s :" % (message))
	if isinstance(answer, basestring):
		return answer.strip().decode('utf-8')
	else:
		return answer
	# Work with Unicode strings internally, converting to a particular encoding on output.

def getGoogleCalendarAPIEntry(c):
	# Return the googleCalendarAPI entry for the GCal Calendar entry
	for g in cfg['googleCalendarAPI']['calendar']:
		if g['calendarAddress'] == c['calendarAddress']:
			return g
	return None

def saveConfigFile():
	global configChanged
	try:
		to_unicode = unicode
	except NameError:
		to_unicode = str

	# Write JSON file
	with io.open(cfgFile, 'w', encoding='utf8') as outfile:
		str_ = json.dumps(cfg,
											indent=2, sort_keys=True,
											separators=(',', ': '), ensure_ascii=False)
		outfile.write(to_unicode(str_))

	configChanged = False

def enterConfigDomoticzTimeZone():
	global cfg
	if not 'timeZone' in cfg['domoticz']: cfg['domoticz']['timeZone'] = ''
	anAnswer = ''
	print '\nThe following question will be about what Time Zone your Domoticz installation operates in. Normally that is the time zone where you live.\n'
	if query_yes_no('Would you like to see a list of all valid time zones', 'yes'):
		for tz in pytz.all_timezones:
			print tz
		print
	
	defaultVal = cfg['domoticz']['timeZone'] if cfg['domoticz']['timeZone'] != '' else ''
	while not anAnswer in pytz.all_timezones:
		anAnswer = default_input('Domoticz Time Zone', defaultVal)
		if not anAnswer in pytz.all_timezones:
			if query_yes_no('That isn\'t a valid time zone! You should write it exactly as it appears in the list. Would you like to see the list of all valid time zones', 'yes'):
				for tz in pytz.all_timezones:
					print tz
				print
	cfg['domoticz']['timeZone'] = anAnswer

def enterConfigDomoticzTextDevStartTimeFmt():
	global cfg
	if not 'textDevStartTimeFmt' in cfg['domoticz']: cfg['domoticz']['textDevStartTimeFmt'] = ''
	defaultVal = cfg['domoticz']['textDevStartTimeFmt'] if cfg['domoticz']['textDevStartTimeFmt'] != '' else '%Y-%m-%d. From %H:%M to '
	cfg['domoticz']['textDevStartTimeFmt'] = default_input('Domoticz text device Start Time format', defaultVal)

def enterConfigDomoticzTextDevEndTimeFmt():
	global cfg
	if not 'textDevEndTimeFmt' in cfg['domoticz']: cfg['domoticz']['textDevEndTimeFmt'] = ''
	defaultVal = cfg['domoticz']['textDevEndTimeFmt'] if cfg['domoticz']['textDevEndTimeFmt'] != '' else '%H:%M'
	cfg['domoticz']['textDevEndTimeFmt'] = default_input('Domoticz text device End Time format', defaultVal)

def enterConfigDomoticzHostName():
	global cfg
	import socket
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('8.8.8.8', 0))	# connecting to a UDP address doesn't send packets
	local_ip_address = s.getsockname()[0]

	if not 'hostName' in cfg['domoticz']: cfg['domoticz']['hostName'] = ''
	defaultVal = cfg['domoticz']['hostName'] if cfg['domoticz']['hostName'] != '' else local_ip_address
	cfg['domoticz']['hostName'] = default_input('Domoticz web interface IP address (or host name)', defaultVal)

def enterConfigDomoticzPortNumber():
	global cfg
	if not 'portNumber' in cfg['domoticz']: cfg['domoticz']['portNumber'] = 0
	defaultVal = cfg['domoticz']['portNumber'] if cfg['domoticz']['portNumber'] != 0 else 8080
	goodInput = False
	while not goodInput:
		try:
			cfg['domoticz']['portNumber'] = default_input('Domoticz web interface port number', defaultVal)
			if cfg['domoticz']['portNumber'] > 0 and cfg['domoticz']['portNumber'] < 65536:
				goodInput = True
			else:
				print("That's not a valid port number. Try again: ")
		except ValueError:
			print('That\'s not an integer. Try again: ')

def enterConfigDomoticzProtocol():
	global cfg
	if not 'protocol' in cfg['domoticz']: cfg['domoticz']['protocol'] = ''
	defaultVal = cfg['domoticz']['protocol'] if cfg['domoticz']['protocol'] != '' else 'http'
	goodInput = False
	while not goodInput:
		cfg['domoticz']['protocol'] = default_input('Domoticz web interface communication protocol (http or https)', defaultVal)
		if cfg['domoticz']['protocol'] == 'http' or cfg['domoticz']['protocol'] == 'https':
			goodInput = True
		else:
			print('That\'s not a valid protocol. Try again: ')

def enterConfigDomoticzUserName():
	global cfg
	if not 'userName' in cfg['domoticz']['httpBasicAuth']: cfg['domoticz']['httpBasicAuth']['userName'] = ''
	defaultVal = cfg['domoticz']['httpBasicAuth']['userName'] if cfg['domoticz']['httpBasicAuth']['userName'] != '' else ''
	cfg['domoticz']['httpBasicAuth']['userName'] = \
					default_input('Domoticz web interface user name (leave blank if no username is needed)', defaultVal)

def enterConfigDomoticzPassWord():
	global cfg
	if not 'passWord' in cfg['domoticz']['httpBasicAuth']: cfg['domoticz']['httpBasicAuth']['passWord'] = ''
	defaultVal = cfg['domoticz']['httpBasicAuth']['passWord'] if cfg['domoticz']['httpBasicAuth']['passWord'] != '' else ''
	cfg['domoticz']['httpBasicAuth']['passWord'] = \
					default_input('Domoticz web interface password (leave blank if no password is needed)', defaultVal)

def enterConfigDomoticzScpHost():
	global cfg
	if not 'scpHost' in cfg['domoticz']: cfg['domoticz']['scpHost'] = ''
	defaultVal = cfg['domoticz']['scpHost'] if cfg['domoticz']['scpHost'] != '' else ''
	cfg['domoticz']['scpHost'] = \
					default_input('Send calendar data with SCP to username@host (leave blank if domoticz is installed on this machine)', defaultVal)

def enterConfigDomoticzScpDir():
	global cfg
	if not 'scpDir' in cfg['domoticz']: cfg['domoticz']['scpDir'] = ''
	defaultVal = cfg['domoticz']['scpDir'] if cfg['domoticz']['scpDir'] != '' else ''
	cfg['domoticz']['scpDir'] = \
					default_input('Send calendar data with SCP to remote directory (leave blank if domoticz is installed on this machine)', defaultVal)

def enterConfigTmpFolder():
	global cfg
	tmpdir = '/var/tmp' if os.path.isdir('/var/tmp') else '/tmp'
	if not 'tmpFolder' in cfg['system']: cfg['system']['tmpFolder'] = ''
	defaultVal = cfg['system']['tmpFolder'] if cfg['system']['tmpFolder'] != '' else tmpdir
	goodInput = False
	while not goodInput:
		cfg['system']['tmpFolder'] = default_input('Directory for app logging and storing access tokens', defaultVal)
		if os.path.isdir(cfg['system']['tmpFolder']):
			goodInput = True
		else:
			print('That isn\'t a valid directory name on your system! Try again: ')

def create_config():
	global cfg;cfg = {}

	data_dir = os.path.join(sys.path[0], '.data')
	if not os.path.exists(data_dir):
		os.makedirs(data_dir)

	cfg['GCal'] = {}
	cfg['GCal']['dbVersion'] = DB_VERSION
	cfg['domoticz'] = {}
	cfg['domoticz']['httpBasicAuth'] = {}
	cfg['calendars'] = {}
	cfg['calendars']['calendar'] = []
	cfg['googleCalendarAPI'] = {}
	cfg['googleCalendarAPI']['calendar'] = []
	cfg['system'] = {}

	enterConfigDomoticzTimeZone()
	enterConfigDomoticzTextDevStartTimeFmt()
	enterConfigDomoticzTextDevEndTimeFmt()
	enterConfigDomoticzHostName()
	enterConfigDomoticzPortNumber()
	enterConfigDomoticzProtocol()
	enterConfigDomoticzUserName()
	enterConfigDomoticzPassWord()
	enterConfigDomoticzScpHost()
	enterConfigDomoticzScpDir()
	enterConfigTmpFolder()


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
		if tty: print r.url
		sys.exit(0)
	if r.status_code <> 200:
		if tty: print 'Unexpected status code from Domoticz: ' + r.status_code + ' Url: ' + r.url
		sys.exit(0)
	try:
		rJsonDecoded = r.json()
	except:
		if tty: print('Can\'t Json decode response from Domoticz.', sys.exc_info()[0])
		sys.exit(0)
	if rJsonDecoded['status'] <> 'OK':
		if tty: print 'Unexpected response from Domoticz: ' + rJsonDecoded['status'] + ' Url: ' + r.url
		if tty: print payload
		sys.exit(0)
	return rJsonDecoded

def logToDomoticz(messageType, logMessage):
	payload = dict([('type', 'command'), ('param', 'addlogmessage'), \
								('message', '(' + messageType+ ') ' + os.path.basename(sys.argv[0]) + ': ' + logMessage)])
	r = domoticzAPI(payload)
	return r

def isUniqueCalShortName(shortName):
	# Check if a unique calendar short name has been given
	for c in cfg['calendars']['calendar']:
		if c['shortName'].lower() == shortName.lower():
			return False
	return True

def createUserVariable(userVariableType, userVariableName):
	payload = dict([('type', 'command'), ('param', 'saveuservariable'), ('vname', userVariableName), \
								('vtype', userVariableType), ('vvalue', 0)])
	r = domoticzAPI(payload)
	# Now go fishing for the newly created user variable to get the idx number
	payload = dict([('type', 'command'), ('param', 'getuservariables')])
	r = domoticzAPI(payload)
	varIdx = 0
	for userVar in reversed(r['result']):
		if userVar['Name'].encode('utf8') == userVariableName:
			varIdx = userVar['idx']
			break
	if varIdx <> '0':
		return varIdx
	else:
		print 'Error: Can not find the newly created Domoticz user variable: ' + userVariableName
		sys.exit(0)

def createConfigEntry():
	entry = {}
	if not tty:
		return entry
	entry['enabled'] = False
	entry['uuid'] = get_a_uuid()

	entry['domoticzSwitchIdx'] = 0
	entry['domoticzTextIdx'] = 0

	entry['shortName'] = ''
	while len(entry['shortName']) < 1:
		entry['shortName'] = default_input('GCal entry short name (Any unique name that You wish to use for this GCal entry) Please keep it very short.', '')
		if len(entry['shortName']) < 1:
			print 'That doesn\'t look like a valid short name'
			print 'Please try again'
		elif not isUniqueCalShortName(entry['shortName']):
			print 'That name is already in use'
			print 'Please try again'
			entry['shortName'] = ''

	match = None
	entry['calendarAddress'] = ''
	while (match == None):
		entry['calendarAddress'] = default_input('Calendar public address (in form of an email address)', '')
		import re
		match = re.match('^[_a-z0-9-\#]+(\.[_a-z0-9-\#]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', entry['calendarAddress'])
		if (match == None):
			print '\'' + entry['calendarAddress'] + '\' doesn\'t look like a valid calendar public address'
			print 'Please try again'

	apiEntry = {}
	if getGoogleCalendarAPIEntry(entry) == None: # We need to create a googleCalendarAPI entry as well
		apiEntry['calendarAddress'] = entry['calendarAddress']
		lastOAuth2ClientID = ''
		lastOAuth2ClientSecret = ''
		if len (cfg['googleCalendarAPI']['calendar']) > 0:
			lastOAuth2ClientID = cfg['googleCalendarAPI']['calendar'][0]['oAuth2ClientCredentials']['clientId']
			lastOAuth2ClientSecret = cfg['googleCalendarAPI']['calendar'][0]['oAuth2ClientCredentials']['clientSecret']

		apiEntry['oAuth2ClientCredentials'] = {}
		apiEntry['oAuth2ClientCredentials']['clientId'] = ''
		while len(apiEntry['oAuth2ClientCredentials']['clientId']) < 10:
			apiEntry['oAuth2ClientCredentials']['clientId'] = default_input('Calendar OAuth2 Client ID:', lastOAuth2ClientID)
			if len(apiEntry['oAuth2ClientCredentials']['clientId']) < 10:
				print 'That doesn\'t look like a valid OAuth2 Client ID'
				print 'Please try again'

		apiEntry['oAuth2ClientCredentials']['clientSecret'] = ''
		while len(apiEntry['oAuth2ClientCredentials']['clientSecret']) < 10:
			apiEntry['oAuth2ClientCredentials']['clientSecret'] = default_input('Calendar OAuth2 Client Secret', lastOAuth2ClientSecret)
			if len(apiEntry['oAuth2ClientCredentials']['clientSecret']) < 10:
				print 'That doesn\'t look like a valid OAuth2 Client Secret'
				print 'Please try again'

	# This is the maximum amount of time in minutes between refreshes of the calendar.
	entry['interval'] = 0
	while entry['interval'] < 5 or entry['interval'] > 60*24*7:
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
		if query_yes_no('Event name and / or description should match the keyword exactly', 'no'):
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

	# Set this to false so that back-to-back events with the same name will be treated as one long event,
	# hence preventing repeating and adjacent all-day events to trip multiple times. Default is False.
	entry['retrip'] = False
	if query_yes_no('Retrip adjacent events with the same name', 'no'):
		entry['retrip'] = True

	domoSwitchDeviceName = 'GCal ' + entry['shortName']
	domoTextDeviceName = 'GCal Status ' + entry['shortName']
	if entry['startDelta'] != 0 or entry['endDelta'] != 0:
		domoSwitchDeviceName = domoSwitchDeviceName + ' (' + str(entry['startDelta']) + ':' + str(entry['endDelta']) + ')'
		domoTextDeviceName = domoTextDeviceName + ' (' + str(entry['startDelta']) + ':' + str(entry['endDelta']) + ')'
	if entry['keyword'] != '':
		keyWords = entry['keyword'].lower().split(';')
		domoSwitchDeviceName = domoSwitchDeviceName + ' kw:' + keyWords[0]
		domoTextDeviceName = domoTextDeviceName + ' kw:' + keyWords[0]

	# Create some Domoticz user variables
	userVariableType = 0 # Integer
	userVariableName = 'GCal-' + entry['shortName'] + '-eventsToday'
	entry['domoticzUVEventsTodayIdx'] = createUserVariable(userVariableType, userVariableName)

	userVariableType = 0 # Integer
	userVariableName = 'GCal-' + entry['shortName'] + '-remainingEventsToday'
	entry['domoticzUVRemainingEventsTodayIdx'] = createUserVariable(userVariableType, userVariableName)

	userVariableType = 2 # Text, maximum size is 200 bytes
	userVariableName = 'GCal-' + entry['shortName'] + '-trippedEvent'
	entry['domoticzUVTrippedEventIdx'] = createUserVariable(userVariableType, userVariableName)

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
		if dev['Name'].encode('utf8') == domoSwitchDeviceName and dev['HardwareID'] == cfg['domoticz']['virtualHwDeviceIdx'] and dev['SubType'] == 'Switch':
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
		if dev['Name'].encode('utf8') == domoTextDeviceName and dev['HardwareID'] == cfg['domoticz']['virtualHwDeviceIdx'] and dev['SubType'] == 'Text':
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

	updateDomoTextDevice(entry, None) # Update the text on the text device

	cfg['calendars']['calendar'].append(entry)
	if 'calendarAddress' in apiEntry:
		cfg['googleCalendarAPI']['calendar'].append(apiEntry)

	saveConfigFile()

	return entry

def updateDomoSwitchDevice(c, tripped, trippedID, trippedEvent, gcalStateEntry):
	if not c['enabled']:
		return

	reTrip = False
	if tripped:
		if gcalStateEntry['tripped']: # It is already tripped before, shall we reTrip it?
			if gcalStateEntry['trippedID'] != trippedID: # The event ID has changed
				if (gcalStateEntry['trippedEvent'].decode('utf-8') ==  trippedEvent): # The event ID has changed but the event name is the same
					if c['retrip']: # Retrip adjacent events with the same name
						reTrip = True
				else:
					# It is already tripped before but now with a different id and a new name
					reTrip = True

	# Get the current switch device value from Domoticz
	payload = dict([('type', 'devices'), ('rid', c['domoticzSwitchIdx'])])
	r = domoticzAPI(payload)

	if not 'result' in r.keys():
		errMess = 'Failure getting data for domoticz device idx: ' + str(c['domoticzSwitchIdx'])
		print errMess
		logToDomoticz(MSG_ERROR, errMess)
		return
	# print r.keys(), r.values()
	domoCompareValue = r['result'][0]['Status']

	if reTrip and domoCompareValue == 'On':
		newValue = 'Off'
		payload = dict([('type', 'command'), ('param', 'switchlight'), ('idx', c['domoticzSwitchIdx']), \
									('switchcmd', newValue)])
		r = domoticzAPI(payload)
		domoCompareValue = 'Off'
		time.sleep(5) # delays for 5 seconds
		# TODO: Try to schedule the next job instead of having a delay here

	newValue = 'On' if tripped else 'Off'
	valueChanged = True if (newValue <> domoCompareValue) else False

	if isDebug:
		print r['result'][0]['Name']
		print 'N: ' + newValue
		print 'D: ' + str(domoCompareValue)
		print
	elif isVerbose and valueChanged:
		sayThis = 'Updating Domoticz device \'' + r['result'][0]['Name'] + '\' idx: ' + str(c['domoticzSwitchIdx']) + ' due to:'
		if valueChanged: sayThis += ' <value changed>. New value is: ' + newValue + \
																'. Old value was: ' + str(domoCompareValue) + '.'
		print sayThis

	if not valueChanged:
		return

	payload = dict([('type', 'command'), ('param', 'switchlight'), ('idx', c['domoticzSwitchIdx']), \
								('switchcmd', newValue)])
	r = domoticzAPI(payload)

def updateDomoUserVars(c, eventsToday, remainingEventsToday, trippedEvent):
	if trippedEvent == None: trippedEvent = TEXT_DEV_NO_EVENT
	userVariableType = 0 # Integer
	varName = 'GCal-' + c['shortName'] + '-eventsToday'
	updateDomoUserVar(userVariableType, c['domoticzUVEventsTodayIdx'], varName, eventsToday)
	varName = 'GCal-' + c['shortName'] + '-remainingEventsToday'
	updateDomoUserVar(userVariableType, c['domoticzUVRemainingEventsTodayIdx'], varName, remainingEventsToday)
	userVariableType = 2 # Text
	varName = 'GCal-' + c['shortName'] + '-trippedEvent'
	updateDomoUserVar(userVariableType, c['domoticzUVTrippedEventIdx'], varName, trippedEvent)

def updateDomoUserVar(userVariableType, idx, varName, newValue):
	# Only update if the new value differs from the previous user variable value
	payload = dict([('type', 'command'), ('param', 'getuservariable'), ('idx', idx)])
	r = domoticzAPI(payload)

	if not 'result' in r.keys():
		errMess = 'Failure getting data for domoticz user variable idx: ' + str(idx)
		if tty: print errMess
		logToDomoticz(MSG_ERROR, errMess)
		return

	domoCompareValue = r['result'][0]['Value']
	if userVariableType == 0: domoCompareValue = int(domoCompareValue)

	valueChanged = False
	if newValue <> domoCompareValue: valueChanged = True
	if isDebug:
		print 'User variable: ' + r['result'][0]['Name']
		try:
			print 'N: ' + str(newValue)
			print 'D: ' + str(domoCompareValue)
		except:
			print 'ascii codec can\'t encode characters, skipping printing that on screen'
		print
	elif isVerbose and valueChanged:
		sayThis = 'Updating Domoticz user variable \'' + r['result'][0]['Name'] + '\' idx: ' + str(idx) + ' due to:'
		if valueChanged: sayThis += ' <value changed>. New value is: ' + str(newValue) + \
																'. Old value was: ' + str(domoCompareValue) + '.'
		try:
			print sayThis
		except:
			print 'ascii codec can\'t encode characters, so skipping printing that on screen'

	if not valueChanged:
		return

	payload = dict([('type', 'command'), ('param', 'updateuservariable'), ('vname', varName), \
								('vtype', userVariableType), ('vvalue', newValue)])
	r = domoticzAPI(payload)


def updateDomoTextDevice(c, eventInfoText):
	if not c['enabled']:
		return
	# Only update if the new value differs from the device value
	# or if the device has not been updated for a while
	payload = dict([('type', 'devices'), ('rid', c['domoticzTextIdx'])])
	r = domoticzAPI(payload)

	if not 'result' in r.keys():
		errMess = 'Failure getting data for domoticz device idx: ' + str(c['domoticzTextIdx'])
		if tty: print errMess
		logToDomoticz(MSG_ERROR, errMess)
		return

	domoCompareValue = r['result'][0]['Data']
	if eventInfoText == None:
		newValue = CAL_NO_FUTURE_EVENTS
	else:
		newValue = eventInfoText

	valueChanged = False
	if newValue <> domoCompareValue: valueChanged = True
	if isDebug:
		print r['result'][0]['Name']
		print 'N: ' + newValue
		print 'D: ' + domoCompareValue
		print
	elif isVerbose and valueChanged:
		sayThis = 'Updating Domoticz device \'' + r['result'][0]['Name'] + '\' idx: ' + str(c['domoticzTextIdx']) + ' due to:'
		if valueChanged: sayThis += ' <value changed>. New value is: ' + newValue + \
																'. Old value was: ' + domoCompareValue + '.'
		print sayThis

	if not valueChanged:
		return

	payload = dict([('type', 'command'), ('param', 'udevice'), ('idx', c['domoticzTextIdx']), \
								('svalue', newValue)])
	r = domoticzAPI(payload)

def get_credentials(g, cred_args):
	"""Gets valid user credentials from storage.

	If nothing has been stored, or if the stored credentials are invalid,
	the OAuth2 flow is completed to obtain the new credentials.

	Returns:
		Credentials, the obtained credential.
	"""
	global lastCredentials
	global lastClientID

	client_id = g['oAuth2ClientCredentials']['clientId']
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
						client_secret=g['oAuth2ClientCredentials']['clientSecret'],
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

def syncWithGoogle(g):
	global cfg
	cred_args = []
	cred_args.append('--noauth_local_webserver')

	# Several GCal entries may use this Google Calendar.
	# Find out the extreme values for startDelta and endDelta so we can determine how much data we need to fetch
	minStartDelta = 0
	maxEndDelta = 0
	maxInterval = 0
	for c in cfg['calendars']['calendar']:
		if c['calendarAddress'] == g['calendarAddress']:
			if c['startDelta'] < minStartDelta:
				minStartDelta = c['startDelta']
			if c['endDelta'] > maxEndDelta:
				maxEndDelta = c['endDelta']
			if c['interval'] > maxInterval:
				maxInterval = c['interval']

	# We won't need to fetch calendar entries older that last midnight + minStartDelta (which might be negative though)
	midnight = datetime.datetime.utcnow().replace(minute=0, hour=0, second=0, microsecond=0)
	timeMin = (midnight + datetime.timedelta(minutes=minStartDelta)) # Limit for historical events
	timeMax = (datetime.datetime.utcnow() + datetime.timedelta(minutes=maxEndDelta) + datetime.timedelta(hours=24)) # Limit for future events
	timeMax = timeMax + datetime.timedelta(minutes=maxInterval) # Add the update interval to timeMax

	timeMin = timeMin.isoformat() + 'Z'
	timeMax = timeMax.isoformat() + 'Z'

	credentials = get_credentials(g, cred_args)
	http = credentials.authorize(httplib2.Http())
	service = discovery.build('calendar', 'v3', http=http)

	logMessage = 'Getting events for calendar ' + g['calendarAddress']
	logToDomoticz(MSG_INFO, logMessage)
	if isVerbose: print logMessage

	eventsResult = service.events().list(
		calendarId=g['calendarAddress'], timeMin=timeMin, timeMax=timeMax, singleEvents=True,
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
	jsonCalFileName = os.path.join(data_dir, str(g['calendarAddress']) + '.json')

	with io.open(jsonCalFileName, 'w', encoding='utf-8') as outfile:
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
		cmd = 'scp ' + jsonCalFileName + ' ' + cfg['domoticz']['scpHost'] + ':' + cfg['domoticz']['scpDir']
		if isVerbose: print cmd
		call(cmd.split(" "))

def load_calendar(g):
	data_dir = os.path.join(cfg['system']['tmpFolder'], 'GCalData')
	jsonCalFileName = os.path.join(data_dir, str(g['calendarAddress']) + '.json')
	try:
		with open(jsonCalFileName) as aFile:
			events = json.load(aFile)
	except:
		logMessage = 'Couldn\'t open the Google Calendar Data json file ' + jsonCalFileName
		if tty: print logMessage, sys.exc_info()[0]
		sys.exit(0)
	return events

#	There are 2 kinds of calendar states
# 1) The Google Calendar states are stored in  google_calendar_states.json
#    A Google Calendar can have many defined GCal entries using different start- and end deltas, keywords etc
#
# 2) The GCal entry states are stored in  gcal_calendar_states.json

def loadGoogleCalStates():
	# The Google calendar state json file holds information about the Google calendar entry states,
	#  this file is dispensable and will be recreated if necessary hence can be stored on a tmpfs drive.

	global googleCalStatesChanged
	global googleCalStates
	data_dir = os.path.join(cfg['system']['tmpFolder'], 'GCalData')
	jsonGoogleCalStateFileName = os.path.join(data_dir, 'google_calendar_states.json')
	try:
		with open(jsonGoogleCalStateFileName) as aFile:
			googleCalStates = json.load(aFile)
	except IOError:
		# We need this file so let's just create one
		googleCalStates = []

		for c in cfg['googleCalendarAPI']['calendar']:
			createGoogleCalStateEntry(c)

	except:
		logMessage = 'Can not open the GCal calendar entry states file ' + jsonGoogleCalStateFileName
		if tty: print logMessage, sys.exc_info()[0]
		sys.exit(0)
	return googleCalStates

def createGoogleCalStateEntry(c):
	global googleCalStatesChanged
	global googleCalStates
	calStateEntry = {}
	calStateEntry['calendarAddress'] = c['calendarAddress']
	calStateEntry['lastCheck'] = (datetime.datetime.now() - datetime.timedelta(days=10)).strftime(dateStrFmt)
	googleCalStates.append(calStateEntry)
	googleCalStatesChanged = True
	return calStateEntry

def getGoogleCalStateEntry(c):
	for cs in googleCalStates:
		if cs['calendarAddress'] == c['calendarAddress']:
			return cs

	logMessage = 'Creating a new Google Calendar state entry for calendar with address: ' + c['calendarAddress']
	if tty: print logMessage
	return createGoogleCalStateEntry(c)

def saveGoogleCalStates():
	global googleCalStatesChanged
	data_dir = os.path.join(cfg['system']['tmpFolder'], 'GCalData')
	jsonGoogleCalStateFileName = os.path.join(data_dir, 'google_calendar_states.json')

	try:
		to_unicode = unicode
	except NameError:
		to_unicode = str

	# Write JSON file
	with io.open(jsonGoogleCalStateFileName, 'w', encoding='utf8') as outfile:
		str_ = json.dumps(googleCalStates,
											indent=2, sort_keys=True,
											separators=(',', ': '), ensure_ascii=False)
		outfile.write(to_unicode(str_))

	googleCalStatesChanged = False

	# Copy the json data to remote host if applicable
	# SSH public-key authentication to connect to a remote system must have been established prior to using
	if len(cfg['domoticz']['scpHost']) > 0 and len(cfg['domoticz']['scpDir']) > 0:
		from subprocess import call
		cmd = 'scp ' + jsonGoogleCalStateFileName + ' ' + cfg['domoticz']['scpHost'] + ':' + cfg['domoticz']['scpDir']
		if isVerbose: print cmd
		call(cmd.split(" "))

def loadGCalStates():
	# The GCal state json file holds information about the GCal entry states,
	#  this file is dispensable and will be recreated if necessary hence can be stored on a tmpfs drive.
	global gcalStatesChanged
	global gcalStates

	data_dir = os.path.join(cfg['system']['tmpFolder'], 'GCalData')
	jsonGcalStateFileName = os.path.join(data_dir, 'gcal_calendar_states.json')
	try:
		with open(jsonGcalStateFileName) as aFile:
			gcalStates = json.load(aFile)
	except IOError:
		# We need this file so let's just create one
		gcalStates = []

		for c in cfg['calendars']['calendar']:
			createGcalStateEntry(c)

	except:
		logMessage = 'Can not open the GCal entry states file ' + jsonGcalStateFileName
		if tty: print logMessage, sys.exc_info()[0]
		sys.exit(0)
	return gcalStates

def createGcalStateEntry(c):
	global gcalStatesChanged
	global gcalStates
	calStateEntry = {}
	calStateEntry['uuid'] = c['uuid']
	calStateEntry['eventsToday'] = 0
	calStateEntry['remainingEventsToday'] = 0
	calStateEntry['tripped'] = False
	calStateEntry['trippedID'] = None
	calStateEntry['trippedEvent'] = None
	calStateEntry['upcomingEvent'] = None
	gcalStates.append(calStateEntry)
	gcalStatesChanged = True
	return calStateEntry

def getGcalStateEntry(c):
	for cs in gcalStates:
		if cs['uuid'] == c['uuid']:
			return cs

	logMessage = 'Creating a new GCal state entry for calendar with UUID: ' + c['uuid']
	if tty: print logMessage
	return createGcalStateEntry(c)

def saveGcalStates():
	global gcalStatesChanged
	data_dir = os.path.join(cfg['system']['tmpFolder'], 'GCalData')
	jsonGcalStateFileName = os.path.join(data_dir, 'gcal_calendar_states.json')

	try:
		to_unicode = unicode
	except NameError:
		to_unicode = str

	# Write JSON file
	with io.open(jsonGcalStateFileName, 'w', encoding='utf8') as outfile:
		str_ = json.dumps(gcalStates,
											indent=2, sort_keys=True,
											separators=(',', ': '), ensure_ascii=False)
		outfile.write(to_unicode(str_))

	gcalStatesChanged = False

	# Copy the json data to remote host if applicable
	# SSH public-key authentication to connect to a remote system must have been established prior to using
	if len(cfg['domoticz']['scpHost']) > 0 and len(cfg['domoticz']['scpDir']) > 0:
		from subprocess import call
		cmd = 'scp ' + jsonGcalStateFileName + ' ' + cfg['domoticz']['scpHost'] + ':' + cfg['domoticz']['scpDir']
		if isVerbose: print cmd
		call(cmd.split(" "))

def process_calendar(c, g, googleCalStateEntry, gcalStateEntry):
	global cfg
	global configChanged
	global googleCalStatesChanged
	global gcalStatesChanged

	events = load_calendar(g)
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
	trippedID = None
	upcomingEvent = None

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
			if startDateTime == endDateTime: # Add 1 minute to zero time event's end time
				endDateTime = endDateTime + datetime.timedelta(minutes=1)

		# Deal with keyword filtering
		if c['keyword'] != '':
			#print 'Keywords in use: ' + c['keyword']
			keyWordFound = False
			keyWords = c['keyword'].lower().split(';')


			for keyWord in keyWords:
				if c['exactKeyword']:
					if not keyWordFound and 'summary' in e: keyWordFound = e['summary'].lower() == keyWord
					if not keyWordFound and 'description' in e: keyWordFound = e['description'].lower == keyWord
				else:
					if not keyWordFound and 'summary' in e: keyWordFound = e['summary'].lower().find(keyWord) != -1
					if not keyWordFound and 'description' in e: keyWordFound = e['description'].lower().find(keyWord) != -1

			if (c['ignoreKeyword'] and keyWordFound) \
			or (not c['ignoreKeyword'] and not keyWordFound):
				#print 'rejects all the remaining statements for event: ' + e['summary']
				continue # rejects all the remaining statements for this event

		# Deal with calendar time offsets
		startDateTime = startDateTime + datetime.timedelta(minutes=c['startDelta'])
		endDateTime = endDateTime + datetime.timedelta(minutes=c['endDelta'])

		# Subtract 1 second from endDateTime so that it will hold the last second that the event is considered active
		endDateTimeMinus1Sec = endDateTime - datetime.timedelta(seconds=1)

		if domoticzNow.date() == startDateTime.date() or domoticzNow.date() == endDateTimeMinus1Sec.date():
			eventsToday = eventsToday + 1
			if domoticzNow <= endDateTimeMinus1Sec:
				remainingEventsToday = remainingEventsToday + 1

		if trippedEvent == None and upcomingEvent == None:
			withinEvent = True if (domoticzNow >= startDateTime) and (domoticzNow <= endDateTimeMinus1Sec) else False
			if startDateTime.hour == 0 and startDateTime.minute == 0 and endDateTime.hour == 0 and endDateTime.minute == 0:
				try:
					eventTimeText = startDateTime.strftime(cfg['domoticz']['textDevAllDayEventFmt'])
				except:
					if tty: print('[\'domoticz\'][\'textDevAllDayEventFmt\'] is missing or faulty. Using the default value.')
					eventTimeText = startDateTime.strftime('%Y-%m-%d. (All day event)')
			else:
				try:
					eventTimeText = startDateTime.strftime(cfg['domoticz']['textDevStartTimeFmt']) + ' ' + \
													endDateTime.strftime(cfg['domoticz']['textDevEndTimeFmt'])
				except:
					if tty: print('[\'domoticz\'][\'textDevStartTimeFmt\'] or [\'domoticz\'][\'textDevStartTimeFmt\'] are missing or faulty.')
					eventTimeText = startDateTime.strftime('%Y-%m-%d. From %H:%M to ') + endDateTime.strftime('%H:%M')
			if withinEvent:
				tripped = True
				trippedEvent = e['summary']
				trippedID = e['id']
				# print trippedEvent # Causes serious error if running in background!!!! 
				# TODO: What if we have more active events? How should they be handled? Now we are only using the first event found that we are within
			elif (domoticzNow < startDateTime):
				upcomingEvent = e['summary']
				#print upcomingEvent # Causes serious error if running in background!!!! 

	#
	#                                ("`-''-/").___..--''"`-._ 
	#                                `6_ 6  )   `-.  (     ).`-.__.`) 
	#                                (_Y_.)'  ._   )  `._ `. ``-..-`  
	#                              _..`--'_..-_/  /--'_.' ,'  
	#                             (il),-''  (li),'  ((!.-'
	#

	seqText = ' ' + str(remainingEventsToday) + '(' + str(eventsToday) + ')'
	if trippedEvent == None and upcomingEvent == None:
		eventInfoText = CAL_NO_FUTURE_EVENTS
		eventTimeText = ''
	elif trippedEvent == None:
		eventInfoText = upcomingEvent
	else:
		eventInfoText = trippedEvent

	if not tripped:
		format1 = '<span style="color: grey;">' # Future events are shown in grey
		format2 = '</span>'
	eventInfoText = format1 + eventInfoText + ' ' + seqText + format2
	if eventTimeText != '': eventInfoText = eventInfoText + '<BR/><span style="font-weight: normal;">' + eventTimeText + '</span>'

	updateDomoUserVars(c, eventsToday, remainingEventsToday, trippedEvent)
	updateDomoTextDevice(c, eventInfoText)
	updateDomoSwitchDevice(c, tripped, trippedID, trippedEvent, gcalStateEntry)

	if gcalStateEntry['tripped'] != tripped \
	or gcalStateEntry['trippedEvent'] != trippedEvent \
	or gcalStateEntry['trippedID'] != trippedID \
	or gcalStateEntry['eventsToday'] != eventsToday \
	or gcalStateEntry['remainingEventsToday'] != remainingEventsToday \
	or gcalStateEntry['upcomingEvent'] != upcomingEvent:
		gcalStateEntry['tripped'] = tripped
		gcalStateEntry['trippedEvent'] = trippedEvent
		gcalStateEntry['trippedID'] = trippedID
		gcalStateEntry['eventsToday'] = eventsToday
		gcalStateEntry['remainingEventsToday'] = remainingEventsToday
		gcalStateEntry['upcomingEvent'] = upcomingEvent
		gcalStatesChanged = True

def list_calendars():
	global cfg
	global googleCalStatesChanged
	global gcalStatesChanged

	global createNewConfigEntry
	while (len(cfg['calendars']['calendar']) < 1) or createNewConfigEntry:
		createConfigEntry()
		if len(cfg['calendars']['calendar']) < 1:
			print 'That didn\'t seem to work.'
		else:
			createNewConfigEntry = False
			cfg = load_config()

	logMessage = 'Found a total of : ' + str(len(cfg['calendars']['calendar'])) + ' GCal entries.\n'
	if isVerbose: logToDomoticz(MSG_INFO, logMessage)
	if isVerbose: print logMessage
	for c in cfg['calendars']['calendar']:
		if c['enabled']:

			g = getGoogleCalendarAPIEntry(c)
			if g == None:
				print('Error: Can not find the Google Calendar API Entry for calendar: ' + c['calendarAddress'])
				continue
			googleCalStateEntry = getGoogleCalStateEntry(c)
			gcalStateEntry = getGcalStateEntry(c)

			elapsed = int((datetime.datetime.now() - datetime.datetime.strptime(googleCalStateEntry['lastCheck'], dateStrFmt)).total_seconds() / 60.0)

			# Check if the raw Google Calendar Data json file exists, it might have disappeared, been deleted or whatever. Maybe it evaporated.
			data_dir = os.path.join(cfg['system']['tmpFolder'], 'GCalData')
			jsonCalFileName = os.path.join(data_dir, str(g['calendarAddress']) + '.json')
			jsonDataAvailable = True if os.path.isfile(jsonCalFileName) else False

			if elapsed >= c['interval'] or not jsonDataAvailable:
				logMessage = 'Syncing Calendar data with Google: ' + g['calendarAddress'] + '. Last fetched: ' + str(elapsed) + ' minutes ago. Interval: ' +str(c['interval'])
				logToDomoticz(MSG_INFO, logMessage)
				if tty: print logMessage
				syncWithGoogle(g)
				googleCalStateEntry['lastCheck'] = datetime.datetime.now().strftime(dateStrFmt)
				googleCalStatesChanged = True
			else:
				if isVerbose:
					logMessage = 'Google Calendar data is up to date: ' + g['calendarAddress'] + '. Last fetched: ' + str(elapsed) + ' minutes ago. Interval: ' +str(c['interval'])
					logToDomoticz(MSG_INFO, logMessage)
					print logMessage
			process_calendar(c, g, googleCalStateEntry, gcalStateEntry)

	if googleCalStatesChanged:
		logMessage = 'Google Calendar states changed... Needs to save'
		if tty: print logMessage
		if isVerbose: logToDomoticz(MSG_INFO, logMessage)
		saveGoogleCalStates()

	if gcalStatesChanged:
		logMessage = 'GCal Calendar states changed... Needs to save'
		if tty: print logMessage
		if isVerbose: logToDomoticz(MSG_INFO, logMessage)
		saveGcalStates()

def reconfigure_gcal_entry(c):
	global cfg
	if query_yes_no('Would you like to reconfigure the GCal Entry with short name: ' + c['shortName'] , 'no'):
		print 'Edit'
	#enterConfigDomoticzTimeZone()

def delete_gcal_entry(c):
	global cfg
	if query_yes_no('Would you like to DELETE the GCal Entry with short name: ' + c['shortName'] , 'no'):
		if query_yes_no('WARNING! This action can not be reverted. Are you sure that you like to DELETE the GCal Entry with short name: ' \
					+ c['shortName'] , 'no'):
			print 'DEEEEEEEEEEEEEEELETE'
			return
	#enterConfigDomoticzTimeZone()

def reconfigure_gcal():
	global cfg
	print '\nYou have requested to reconfigure GCal. First You have the option to alter the common GCal settings. For each setting you will be prompted with its current value and you will be able to alter it. After that, for each previously defined GCal entry, you will have the choice to delete it or to reconfigure it.\n'
	if not query_yes_no('Are You sure that you\'d like to reconfigure GCal now', 'no'):
		sys.exit(0)

	if query_yes_no('Would you like to reconfigure the common GCal settings now', 'no'):
		enterConfigDomoticzTimeZone()
		enterConfigDomoticzTextDevStartTimeFmt()
		enterConfigDomoticzTextDevEndTimeFmt()
		enterConfigDomoticzHostName()
		enterConfigDomoticzPortNumber()
		enterConfigDomoticzProtocol()
		enterConfigDomoticzUserName()
		enterConfigDomoticzPassWord()
		enterConfigDomoticzScpHost()
		enterConfigDomoticzScpDir()
		enterConfigTmpFolder()

	print '\nWe will now go through all your defined GCal Entries.'
	print 'You will have the option to either delete or to reconfigure each entry.\n'

	print '\n\nEntering DELETE stage for GCal Entries'
	for c in cfg['calendars']['calendar']:
		delete_gcal_entry(c)
		saveConfigFile()
		load_config()

	if len(cfg['calendars']['calendar']) < 1:
		print '\nYou have deleted all your GCal entries. You should now run this command with the -c flag to create a GCal entry.'
		sys.exit(0)

	print '\n\nEntering reconfiguring stage for GCal Entries'
	for c in cfg['calendars']['calendar']:
		reconfigure_gcal_entry(c)

	saveConfigFile()

	print '\nGCal has been reconfigured'


def print_help(argv):
	print 'usage: ' + os.path.basename(__file__) + ' [option] [-C domoticzDeviceidx|all] \nOptions and arguments'
	print '-d		 : debug output (also --debug)'
	print '-h		 : print this help message and exit (also --help)'
	print '-v		 : verbose'
	print '-V		 : print the version number and exit (also --version)'
	print '-c		 : create an additional GCal entry (also --create_gcal_entry)'
	print '-r		 : reconfigure GCal (also --reConfigure)'

def main(argv):
	if os.geteuid() == 0:
		sys.exit('\nThis script should not be run as user \'root\'\n')
	global isDebug
	global isVerbose
	global reConfigure

	global createNewConfigEntry;createNewConfigEntry = False
	try:
		opts, args = getopt.getopt(argv, 'dhvVcr', ['help', 'debug', 'version', 'create_gcal_entry', 'reconfigure'])
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
		elif opt in ("-r", "--reconfigure"):
			reConfigure = True

	if isDebug: print 'Debug is on'
	if not tty: time.sleep( 5 ) # Give Domoticz some time to settle down from other commands running exactly at the 00 sec
	global cfg; cfg = load_config()
	global googleCalStates; googleCalStates = loadGoogleCalStates()
	global gcalStates; gcalStates = loadGCalStates()
	#global logFile; logFile = os.path.join(cfg['system']['tmpFolder'], os.path.basename(sys.argv[0]) + '.log')

	if not connected_to_internet():
		logToDomoticz(MSG_ERROR, 'No internet connection available')
		sys.exit(0)

	msgProgInfo = APPLICATION_NAME + ' Version ' + VERSION
	msgProgInfo += ' (DB version ' + cfg['GCal']['dbVersion'] + ')'

	msgProgInfo += ' running on TTY console...' if tty else ' running as a CRON job...'
	logToDomoticz(MSG_EXEC, msgProgInfo)
	if isVerbose: print msgProgInfo

	if reConfigure and tty:
		reconfigure_gcal()

	list_calendars()
	sys.exit(0)

if __name__ == '__main__':
	main(sys.argv[1:])
