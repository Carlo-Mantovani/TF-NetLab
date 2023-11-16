sudo docker network create --driver=bridge --subnet=172.20.0.0/16 br0
sudo docker run --network=br0 --name=host -d python:3.8 
sudo docker cp ./send.py host:./
sudo docker exec -it host sh

sudo docker stop host
sudo docker rm host