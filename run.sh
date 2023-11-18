#!/usr/bin/env sh

# Docker compose build
sudo docker-compose up -d --build

# Allow traffic between containers in different networks
sudo iptables -I DOCKER-ISOLATION-STAGE-2 -o br0 -i br1 -j ACCEPT
sudo iptables -I DOCKER-ISOLATION-STAGE-2 -o br1 -i br0 -j ACCEPT

# Exec attacker container
sudo docker-compose run --rm attacker zsh
