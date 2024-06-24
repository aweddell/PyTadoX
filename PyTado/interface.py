"""
PyTado interface implementation for mytado.com
"""

import logging
import json
import datetime
import urllib.request
import urllib.parse
import urllib.error

from http.cookiejar import CookieJar


_LOGGER = logging.getLogger(__name__)


class Tado:
    """Interacts with a Tado thermostat via public API.
    Example usage: t = Tado('me@somewhere.com', 'mypasswd')
                   t.getClimate(1) # Get climate, zone 1.
    """

    _debugCalls = False

    # Instance-wide constant info
    headers = {'Referer' : 'https://my.tado.com/'}
    api2url = 'https://my.tado.com/api/v2/homes/'
    mobi2url = 'https://my.tado.com/mobile/1.9/'
    headersX = {'Referer' : 'https://app.tado.com/'}
    apiXurl = 'https://hops.tado.com/homes/'
    refresh_token = ''
    refresh_at = datetime.datetime.now() + datetime.timedelta(minutes=5)
    isX = False

    # 'Private' methods for use in class, Tado mobile API V1.9.
    def _mobile_apiCall(self, cmd):
        # pylint: disable=C0103

        if isX:
            self._refresh_tokenX()
        else:
            self._refresh_token()

        if self._debugCalls:
            _LOGGER.debug("mobile api: %s",
                          cmd)

        url = '%s%s' % (self.mobi2url, cmd)
        req = urllib.request.Request(url, headers=self.headers)
        response = self.opener.open(req)
        str_response = response.read().decode('utf-8')

        if self._debugCalls:
            _LOGGER.debug("mobile api: %s, response: %s",
                          cmd, response)

        data = json.loads(str_response)
        return data

    # 'Private' methods for use in class, Tado API V2.
    def _apiCall(self, cmd, method="GET", data=None, plain=False):
        # pylint: disable=C0103

        """
        Check if we are hitting a TadoX home, and adjust
        """
        if self.isX:
            self._refresh_tokenX()
            headers = self.headersX
            url = '%s%i/%s' % (self.apiXurl, self.id, cmd)
        else:
            self._refresh_token()
            headers = self.headers
            url = '%s%i/%s' % (self.api2url, self.id, cmd)

        if data is not None:
            if plain:
                headers['Content-Type'] = 'text/plain;charset=UTF-8'
            else:
                headers['Content-Type'] = 'application/json;charset=UTF-8'
            headers['Mime-Type'] = 'application/json;charset=UTF-8'
            data = json.dumps(data).encode('utf8')

        if self._debugCalls:
            _LOGGER.debug("api call: %s: %s, headers %s, data %s",
                          method, cmd, headers, data)

        req = urllib.request.Request(url,
                                     headers=headers,
                                     method=method,
                                     data=data)

        response = self.opener.open(req)

        if self._debugCalls:
            _LOGGER.debug("api call: %s: %s, response %s",
                          method, cmd, response)

        str_response = response.read().decode('utf-8')
        if str_response is None or str_response == "":
            return

        data = json.loads(str_response)
        return data

    def _setOAuthHeader(self, data):
        # pylint: disable=C0103

        access_token = data['access_token']
        expires_in = float(data['expires_in'])
        refresh_token = data['refresh_token']

        self.refresh_token = refresh_token
        self.refresh_at = datetime.datetime.now()
        self.refresh_at = self.refresh_at + datetime.timedelta(seconds=expires_in)

        # we substract 30 seconds from the correct refresh time
        # then we have a 30 seconds timespan to get a new refresh_token
        self.refresh_at = self.refresh_at + datetime.timedelta(seconds=-30)

        if self.isX:
            self.headersX['Authorization'] = 'Bearer ' + access_token
        else:
            self.headers['Authorization'] = 'Bearer ' + access_token

    def _refresh_token(self):
        if self.refresh_at >= datetime.datetime.now():
            return False

        url = 'https://auth.tado.com/oauth/token'
        data = {'client_id' : 'public-api-preview',
                'client_secret' : '4HJGRffVR8xb3XdEUQpjgZ1VplJi6Xgw',
                'grant_type' : 'refresh_token',
                'scope' : 'home.user',
                'refresh_token' : self.refresh_token}
        # pylint: disable=R0204
        data = urllib.parse.urlencode(data)
        url = url + '?' + data
        req = urllib.request.Request(url, data=json.dumps({}).encode('utf8'), method='POST',
                                     headers={'Content-Type': 'application/json',
                                              'Referer' : 'https://my.tado.com/'})

        response = self.opener.open(req)
        str_response = response.read().decode('utf-8')

        self._setOAuthHeader(json.loads(str_response))
        return response
     
    def _refresh_tokenX(self):
        """
        Tado X API doesn't yet accept public-api-preview client.
        Use the webapp client ID and secret to auth for now.
        TODO: Change this out when Tado fixes this.
        """
        if self.refresh_at >= datetime.datetime.now():
            return False

        url = 'https://auth.tado.com/oauth/token'
        data = {'client_id' : 'tado-web-app',
                'client_secret' : 'wZaRN7rpjn3FoNyF5IFuxg9uMzYJcvOoQ8QWiIqS3hfk6gLhVlG57j5YNoZL2Rtc',
                'grant_type' : 'refresh_token',
                'scope' : 'home.user',
                'refresh_token' : self.refresh_token}
        # pylint: disable=R0204
        data = urllib.parse.urlencode(data)
        url = url + '?' + data
        req = urllib.request.Request(url, data=json.dumps({}).encode('utf8'), method='POST',
                                     headers={'Content-Type': 'application/json',
                                              'Referer' : 'https://app.tado.com/'})

        response = self.opener.open(req)
        str_response = response.read().decode('utf-8')

        self._setOAuthHeader(json.loads(str_response))
        return response

    def _loginV2(self, username, password):
        # pylint: disable=C0103

        headers = self.headers
        headers['Content-Type'] = 'application/json'

        url = 'https://auth.tado.com/oauth/token'
        data = {'client_id' : 'public-api-preview',
                'client_secret' : '4HJGRffVR8xb3XdEUQpjgZ1VplJi6Xgw',
                'grant_type' : 'password',
                'password' : password,
                'scope' : 'home.user',
                'username' : username}
        # pylint: disable=R0204
        data = urllib.parse.urlencode(data)
        url = url + '?' + data
        req = urllib.request.Request(url, data=json.dumps({}).encode('utf8'), method='POST',
                                     headers={'Content-Type': 'application/json',
                                              'Referer' : 'https://my.tado.com/'})

        response = self.opener.open(req)
        str_response = response.read().decode('utf-8')

        self._setOAuthHeader(json.loads(str_response))
        return response
    
    def _loginX(self, username, password):
        """
        Tado X API doesn't yet accept public-api-preview client.
        Use the webapp client ID and secret to auth for now.
        TODO: Change this out when Tado fixes this.
        """
        # pylint: disable=C0103

        headers = self.headersX
        headers['Content-Type'] = 'application/json'

        url = 'https://auth.tado.com/oauth/token'
        data = {'client_id' : 'tado-web-app',
                'client_secret' : 'wZaRN7rpjn3FoNyF5IFuxg9uMzYJcvOoQ8QWiIqS3hfk6gLhVlG57j5YNoZL2Rtc',
                'grant_type' : 'password',
                'password' : password,
                'scope' : 'home.user',
                'username' : username}
        # pylint: disable=R0204
        data = urllib.parse.urlencode(data)
        url = url + '?' + data
        req = urllib.request.Request(url, data=json.dumps({}).encode('utf8'), method='POST',
                                     headers={'Content-Type': 'application/json',
                                              'Referer' : 'https://app.tado.com/'})

        response = self.opener.open(req)
        str_response = response.read().decode('utf-8')

        self._setOAuthHeader(json.loads(str_response))
        return response

    def setDebugging(self, debugCalls):
        self._debugCalls = debugCalls
        return self._debugCalls

    # Public interface
    def getMe(self):
        """Gets user information, including home ID."""
        # pylint: disable=C0103

        url = 'https://my.tado.com/api/v2/me'
        req = urllib.request.Request(url, headers=self.headers)
        response = self.opener.open(req)
        str_response = response.read().decode('utf-8')
        data = json.loads(str_response)
        return data
    
    def getHome(self):
        """Gets home information."""
        
        cmd = ''
        
        data = self._apiCall(cmd)
        return data

    def getDevices(self):
        """Gets device information."""
        # pylint: disable=C0103

        if self.isX:
            cmd = 'roomsAndDevices'
        else:
            cmd = 'devices'
        
        data = self._apiCall(cmd)
        return data

    def getZones(self):
        """Gets zones information."""
        # pylint: disable=C0103

        if self.isX:
            cmd = 'rooms'
        else:
            cmd = 'zones'
        data = self._apiCall(cmd)
        return data

    def getState(self, zone):
        """Gets current state of Zone zone."""
        # pylint: disable=C0103

        
        if self.isX:
            cmd = 'rooms/%i' % zone
        else:
            cmd = 'zones/%i/state' % zone
        
        data = self._apiCall(cmd)
        return data

    def getCapabilities(self, zone):
        """Gets current capabilities of Zone zone."""
        # pylint: disable=C0103
        if self.isX:
            return False
        
        cmd = 'zones/%i/capabilities' % zone
        data = self._apiCall(cmd)
        return data

    def getClimate(self, zone):
        """Gets temp (centigrade) and humidity (% RH) for Zone zone."""
        # pylint: disable=C0103

        data = self.getState(zone)['sensorDataPoints']
        return {'temperature' : data['insideTemperature']['celsius'],
                'humidity'    : data['humidity']['percentage']}

    def getWeather(self):
        """Gets outside weather data"""
        # pylint: disable=C0103

        cmd = 'weather'
        data = self._apiCall(cmd)
        return data

    def getAppUsers(self):
        """Gets getAppUsers data"""
        # pylint: disable=C0103

        cmd = 'getAppUsers'
        data = self._mobile_apiCall(cmd)
        return data

    def getAppUsersRelativePositions(self):
        """Gets getAppUsersRelativePositions data"""
        # pylint: disable=C0103

        cmd = 'getAppUsersRelativePositions'
        data = self._mobile_apiCall(cmd)
        return data

    def resetZoneOverlay(self, zone):
        """Delete current overlay"""
        # pylint: disable=C0103

        if self.isX:
            cmd = 'rooms/%i/resumeSchedule' % zone
            data = self._apiCall(cmd, "POST", {}, True)
        else:
            cmd = 'zones/%i/overlay' % zone
            data = self._apiCall(cmd, "DELETE", {}, True)
        
        return data

    def setZoneOverlay(self, zone, overlayMode, setTemp=None, duration=None, deviceType='HEATING', power="ON", mode=None):
        """set current overlay for a zone"""
        # pylint: disable=C0103

        if self.isX:
            cmd = 'rooms/%i/manualControl' % zone
            method = 'POST'
            tempParam = 'value'
        else:
            cmd = 'zones/%i/overlay' % zone
            method='PUT'
            tempParam = 'celsius'

        post_data = {
            "setting" : {},
            "termination" : {}
        }

        if setTemp is None:
            post_data["setting"] = {
                "type": deviceType,
                "power": power
            }
        elif mode is not None:
            post_data["setting"] = {
                "type": deviceType,
                "power": power,
                "mode": mode,
                "temperature":{
                    tempParam: setTemp
                }
            }
        else:
            post_data["setting"] = {
                "type": deviceType,
                "power": power,
                "temperature":{
                    tempParam: setTemp
                }
            }

        post_data["termination"] = {"type" : overlayMode}

        if duration is not None:
            post_data["termination"]["durationInSeconds"] = duration

        data = self._apiCall(cmd, method, post_data)
        return data

    # Ctor
    def __init__(self, username, password):
        """Performs login and save session cookie."""
        # HTTPS Interface

        # pylint: disable=C0103
        cj = CookieJar()

        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            urllib.request.HTTPSHandler())
        self._loginV2(username, password)
        self.id = self.getMe()['homes'][0]['id']
        
        if self.getHome()['generation'] == 'LINE_X':
            _LOGGER.debug("Detected a Tado X installation, reauthenticating and setting isX True")
            self.isX = True
            self._loginX(username, password)