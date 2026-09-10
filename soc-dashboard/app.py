from flask import Flask, render_template, jsonify, request
import requests
import json
import subprocess
import re

app = Flask(__name__)

OPNSENSE_IP = "10.0.3.1"
OLLAMA_URL = "http://10.0.3.100:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"

def get_alerts_ssh():
    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             "root@" + OPNSENSE_IP,
             "cat /var/log/suricata/eve.json | grep event_type | grep alert | tail -20"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().split("\n")
        alerts = []
        for line in lines:
            if line.strip():
                try:
                    alerts.append(json.loads(line))
                except:
                    pass
        return alerts
    except Exception as e:
        return {"error": str(e)}

def analyze_with_ai(alerts_text):
    try:
        prompt = """You are a SOC analyst. Analyze these Suricata alerts. Reply with ONLY a valid JSON array. No explanations, no markdown, no text before or after the JSON.

Example of the EXACT format you must use:
[{"signature":"ET SCAN Nmap","severity":"medium","category":"Network Scan","src_ip":"10.0.1.50","dst_ip":"10.0.1.10","protocol":"TCP","description":"Escaneo de puertos detectado desde la red interna hacia el servidor DMZ.","impact":"El atacante puede descubrir servicios expuestos y vulnerabilidades.","mitigations":["Bloquear IP origen en el firewall","Revisar servicios expuestos","Implementar rate limiting"],"suricata_rule":"drop tcp any any -> $HOME_NET any (msg:SCAN blocked; threshold:type limit,track by_src,count 1,seconds 60; sid:9000001; rev:1;)","mitre_attack":"TA0043 Reconnaissance - T1046 Network Service Discovery"}]

ALERTS TO ANALYZE:
""" + alerts_text

        resp = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 4096
            }
        }, timeout=180)
        data = resp.json()
        text = data.get("response", "")
        clean = text.strip()
        clean = clean.replace("```json", "").replace("```", "").strip()
        try:
            return json.loads(clean)
        except:
            match = re.search(r'\[[\s\S]*?\]', clean)
            if match:
                try:
                    return json.loads(match.group())
                except:
                    pass
            return {"error": "No se pudo parsear la respuesta del modelo: " + clean[:300]}
    except requests.exceptions.Timeout:
        return {"error": "Timeout: el modelo tardo demasiado. Intenta con menos alertas."}
    except Exception as e:
        return {"error": str(e)}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/alerts")
def api_alerts():
    alerts = get_alerts_ssh()
    return jsonify(alerts)

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.json
    alerts_raw = data.get("alerts", "")
    try:
        parsed = json.loads(alerts_raw)
        if isinstance(parsed, list):
            short = []
            for a in parsed[:5]:
                short.append({
                    "signature": a.get("alert", {}).get("signature", "Unknown"),
                    "category": a.get("alert", {}).get("category", "Unknown"),
                    "severity": a.get("alert", {}).get("severity", 3),
                    "src_ip": a.get("src_ip", ""),
                    "dst_ip": a.get("dest_ip", ""),
                    "proto": a.get("proto", ""),
                    "dest_port": a.get("dest_port", "")
                })
            alerts_raw = json.dumps(short)
    except:
        pass
    result = analyze_with_ai(alerts_raw)
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
