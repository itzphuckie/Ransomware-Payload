import requests
import json

url = 'https://api.random.org/json-rpc/1/invoke'

data = {'jsonrpc':'2.0','method':'generateIntegers','params':{'apiKey':'2e8c8682-b278-40b4-923e-287fa18c205e','n':10,'min':1,'max':10,'replacement':'true','base':10},'id':24565}

params = json.dumps(data)

response = requests.post(url,params)

print(response.text)
