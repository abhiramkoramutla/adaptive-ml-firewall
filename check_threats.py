import urllib.request
import json
try:
    resp = urllib.request.urlopen("http://localhost:5000/api/threats")
    data = json.loads(resp.read().decode())
    for t in data[:5]:
        print(f"{t.get('attack_type')} - {t.get('prediction')} ({t.get('packet_rate')} pkt/s) [Confidence: {t.get('confidence')}]")
except Exception as e:
    print(e)
