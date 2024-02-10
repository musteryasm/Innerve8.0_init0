from django.shortcuts import render
from manuf import manuf
import nmap
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Alert
from .serializers import AlertSerializer
import json
from datetime import datetime
from .models import Alert, MaliciousRequests
from django.db.models import Count
import pandas as pd
from .serializers import MaliciousRequestsSerializer

def analysis(request):
    csv = pd.read_csv(r'CICFlowmeter\bin\data\daily\2024-02-10_Flow.csv')
    # print(csv)
    src_ip_column = 'Src IP'
    value_to_count = '192.168.127.160'
    total_requests= csv.shape[0]
    outgoing_requests= csv[src_ip_column].value_counts().get(value_to_count, 0)
    incoming_requests = total_requests - outgoing_requests
    context = {
        'total_requests': total_requests,
        'incoming_requests': incoming_requests,
        'outgoing_requests': outgoing_requests,
    }
    return render(request, 'analysis.html')


def alerts(request):
    # Retrieve all alerts from the database, ordered by AlertTime in descending order
    alerts_list = Alert.objects.all().order_by('-AlertTime')
    malicious_list = MaliciousRequests.objects.all()
    # for malicious in malicious_list:
    #     print(malicious.check)
    # Pass the list of alerts to the template
    context = {'alerts_list': alerts_list, 'malicious_list': malicious_list}
    
    return render(request, 'alerts.html', context)


class ReceiveAlert(APIView):
    def post(self, request, format=None):
        try:
            data = json.loads(request.body)
            alert_message = data.get('AlertMessage', {})  # Extract 'AlertMessage' from the received JSON
            print(data)
            alert_info = {
                'Category': alert_message.get('Category', ''),
                'DetectionType': alert_message.get('DetectionType', ''),
                'User': alert_message.get('User', ''),
                'Name': alert_message.get('Name', ''),
                'Severity': alert_message.get('Severity', ''),
                'ProcessName': alert_message.get('ProcessName', ''),
                'Path': alert_message.get('Path', ''),
                'DetectionOrigin': alert_message.get('DetectionOrigin', ''),
                'Message': alert_message.get('Message', ''),
                'MACAddress': alert_message.get('MACAddress', '')
            }

            alert_time_str = data.get('AlertTime', '')  # Extract 'AlertTime' as string
            alert_time = datetime.strptime(alert_time_str, '%m-%d-%Y %H:%M:%S') if alert_time_str else None

            alert_info['AlertTime'] = alert_time  # Assign 'AlertTime' to the prepared dictionary

            alert_serializer = AlertSerializer(data=alert_info)
            if alert_serializer.is_valid():
                alert_serializer.save(AlertTime=alert_time)
                return Response("Data saved successfully", status=status.HTTP_201_CREATED)
            else:
                print("Serializer Errors:", alert_serializer.errors)
                return Response(alert_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except json.JSONDecodeError:
            return Response("Invalid JSON format", status=status.HTTP_400_BAD_REQUEST)

class ReceiveMaliciousRequests(APIView):
    def post(self, request, format=None):
        try:
            data = json.loads(request.body)
            serializer = MaliciousRequestsSerializer(data=data)

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON format'}, status=status.HTTP_400_BAD_REQUEST)
            
        


def get_mac_addresses():
    nm = nmap.PortScanner()
    nm.scan(hosts="192.168.127.1/24", arguments='-sn')
    devices = []
    for host in nm.all_hosts():
        host_info = nm[host]
        ipv4 = host_info['addresses'].get('ipv4', '-')
        mac_address = host_info['addresses'].get('mac', '-')
        device_name = host_info['vendor'].get(mac_address, '-')
        devices.append({"ip": ipv4, "mac": mac_address, "device_info": device_name})
    return devices
# sample_devices = [
#     {"ip": "192.168.0.1", "mac": "00:11:22:33:44:55", "device_info": "Router"},
#     {"ip": "192.168.0.2", "mac": "AA:BB:CC:DD:EE:FF", "device_info": "Desktop PC"},
#     {"ip": "192.168.0.3", "mac": "12:34:56:78:90:AB", "device_info": "Smartphone"},
# ]
def index(request):
    # device_info = get_mac_addresses()
    top_alerts = (Alert.objects.values('MACAddress', 'Category').annotate(alert_count=Count('id')).order_by('-alert_count')[:3])
    device_info = get_mac_addresses()
    csv = pd.read_csv(r'CICFlowmeter\bin\data\daily\2024-02-10_Flow.csv')
    # print(csv)
    src_ip_column = 'Src IP'
    value_to_count = '192.168.127.160'
    total_requests= csv.shape[0]
    outgoing_requests= csv[src_ip_column].value_counts().get(value_to_count, 0)
    incoming_requests = total_requests - outgoing_requests
    context = {
        'total_requests': total_requests,
        'incoming_requests': incoming_requests,
        'outgoing_requests': outgoing_requests,
        'device_info': device_info,
        'top_alerts': top_alerts,
    }
    return render(request, 'index.html', context)
