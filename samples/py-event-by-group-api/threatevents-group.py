import requests
import jwt
import time
import json
import urllib.parse


class IamParameters:
    def __init__(self, iamUrl, clientId, clientSecret, scopes):
        self.iamUrl = iamUrl
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.scopes = scopes

class ApiParameters:
    def __init__(self, apiUrl, apiKey):
        self.apiUrl = apiUrl
        self.apiKey = apiKey


iamParameters = IamParameters("https://iam.mcafee-cloud.com/iam/v1.1/token",
    "clientId",
    "clientSecret",
    "epo.evt.r epo.device.r epo.tags.r epo.tags.w epo.device.w epo.grps.r")

apiParameters = ApiParameters("https://api.mvision.mcafee.com","apiKey")

groupName = "GROUPNAME"

def isValidToken(token) :
    if token is None : return False
    decoded = jwt.decode(token, options = { "verify_signature" : False})
    expiry = decoded["exp"]
    if expiry is None : return False
    if expiry < int(time.time()) : return False
    return True


'''
Checks the current token for expiry. If valid, returns token, else fetches a new one from IAM
'''
def getToken(current , iam : IamParameters) : 
    if not isValidToken(current):
        print(f"Requesting scope {iam.scopes}")
        params = { 'grant_type' : 'client_credentials', 'scope' : iam.scopes }
        response = requests.get(iam.iamUrl, auth=(iam.clientId, iam.clientSecret), params=params, verify=False)
        if response.status_code == 200 :
            r = response.json()
            return r["access_token"]
        else : 
            raise Exception('Unable to get token')        
    else:
        return current


def getGroupsIdForName(token, name , iam : IamParameters, api : ApiParameters) :
    print(f"Getting groups")
    url = api.apiUrl + "/epo/v1/groups"

    params={
        "$filter" : json.dumps({ "name" : name })
    }

    token=getToken(token, iam)
    headers={
        "content-type" : "application/vnd.api+json",
        "x-api-key" : api.apiKey,
        "authorization" : "Bearer " + token
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return data["data"]["items"][0]["id"]
    else:
        raise Exception(f"Unable to get groups by update time {response.status_code}")
        

def getGroupNodePath(token, groupId, iam : IamParameters, api : ApiParameters):
    print(f"Getting groups")
    url = api.apiUrl + "/epo/v2/groups/" + str(groupId)

    token=getToken(token, iam)
    headers={
        "content-type" : "application/vnd.api+json",
        "x-api-key" : api.apiKey,
        "authorization" : "Bearer " + token
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data["data"]["attributes"]["nodePath"]
    else:
        raise Exception(f"Unable to get groups by update time {response.status_code}")

def fetchEvents(token, startTime, nodePath , iam : IamParameters, api : ApiParameters ) :
    url = api.apiUrl + "/epo/v2/events"
    nextItem = None
    hasMore = True
    events = []
    while (hasMore) :
        token  = getToken(token, iam)
        params = {
            'filter[timestamp][GE]' : startTime
        }
        headers={ 
            "content-type" : "application/vnd.api+json", 
            "x-api-key" : api.apiKey,
            "authorization" : "Bearer " + token
        }        
        if nextItem: 
            url = nextItem
            params = {}
        
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()            
            if data and data.get("links") and data.get("links").get("next"):
                nextItem = data["links"]["next"]
                hasMore = True
            else:
                hasMore=False
            events.extend(  list(filter(lambda x: (x["attributes"]["nodepath"] == nodePath),  data["data"])))  
            return events
        else:
            raise Exception(f"Error getting threat events from MVISION {response.status_code}")

startTime = "2021-05-08T00:00:00.000"


t = getToken(None, iamParameters)
groupId = getGroupsIdForName(token=t, iam=iamParameters, api=apiParameters, name=groupName)
nodepath = getGroupNodePath(token=t,groupId=groupId, iam=iamParameters, api=apiParameters)
events = fetchEvents(token=t, startTime=startTime, iam=iamParameters,api=apiParameters, nodePath=nodepath)
print(f"{events}")
