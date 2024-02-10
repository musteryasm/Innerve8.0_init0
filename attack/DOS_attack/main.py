
import requests
import time
import uuid

def main():
    attacker_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)]) 
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    

    payload = {
        "Attacker": attacker_mac,
        "AlertTime": current_time
    }

    try:
        response = requests.post("http://192.168.127.160:8000/api/receive_malicious_alert/", json=payload)
        print("Response:", response.text)
    except Exception as e:
        print("Error occurred during request:", e)

if __name__ == "__main__":
    main()
