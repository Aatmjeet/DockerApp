## git clone https://github.com/Aatmjeet/DockerApp
## cd DockerApp/WebApp
## sudo apt-get isntall build-essesntial
## python3 -m venv auth
## source auth/bin/activate
## pip install requirements.txt
## cd ..
## ./run_docker.sh

# This commands connects to bash in nginx continer
## sudo docker exec -it nginx bash
### after we get into the container,
### certbot --nginx -d minskin.store -d www.minskin.store
