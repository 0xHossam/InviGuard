import requests
import json

# URL of the server
base_url = 'HTTP://127.0.0.1:5000'

def get_alerts():

    url = f'{ base_url }/get_alerts'
    response = requests.get( url )

    if response.status_code == 200:
        alerts = response.json()
        print('Alerts:', json.dumps( alerts , indent = 4 ))
    else:
        print(f'Failed to get alerts: { response.status_code }')
        print( response.text )

# Get all alerts
get_alerts()