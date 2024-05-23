from flask import Flask, render_template, request, jsonify
from configs.config_loader import load_config, save_config

app = Flask(__name__)
alerts = []  # This will store the alerts in memory

@app.route('/api/add_alert', methods=['POST'])
def api_add_alert():
    alert_data = request.get_json()
    add_alert(alert_data)
    return {'status': 'success'}, 200

@app.route('/api/config', methods=['GET'])
def api_get_config():
    return jsonify(load_config())

@app.route('/api/config', methods=['POST'])
def api_update_config():
    new_config = request.get_json()
    save_config(new_config)
    return {'status': 'updated'}, 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_alerts')
def get_alerts():
    return jsonify(alerts)

def add_alert(alert_data):
    global alerts  
    alerts.append(alert_data)
    print(f"Alert added: {alert_data}")

if __name__ == '__main__':
    app.run(debug=True)
