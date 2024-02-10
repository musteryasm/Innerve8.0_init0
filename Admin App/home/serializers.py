from rest_framework import serializers
from .models import Alert
from .models import MaliciousRequests

class MaliciousRequestsSerializer(serializers.ModelSerializer):
    class Meta:
        model = MaliciousRequests
        fields = ['AlertTime', 'Attacker']

        
class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ('Category', 'DetectionType', 'User', 'Name', 'Severity', 'ProcessName', 'Path', 'DetectionOrigin', 'Message', 'AlertTime', 'MACAddress')
