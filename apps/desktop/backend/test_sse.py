import urllib.request
import time

url = 'http://localhost:8000/api/v1/audit/scan/stream?repo_url=https://github.com/test/test'
req = urllib.request.Request(url, headers={'Accept': 'text/event-stream'})

try:
    with urllib.request.urlopen(req) as response:
        print('Connected to stream')
        for line in response:
            line_str = line.decode('utf-8').strip()
            if line_str:
                print('Received:', line_str)
except Exception as e:
    print('Error:', e)
