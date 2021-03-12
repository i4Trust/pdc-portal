# pdc-portal

Packet Delivery Portal application for i4Trust experimentation framework

## Configuration

Configuration is done in the file `config/pdc-portal.yml`. You need to modify the values according to your 
environment and add your private key and certificate chain.

## Usage

### Local

Run locally using `node.js`:
```shell
npm install
npm start
```


### Docker

A Dockerfile is provided for building the image:
```shell
docker build -t pdc-portal:my-tag .
```

Make a copy of the configuration file `config/pdc-portal.yml` and modify according to your environment. 
Then run the image:
```shell
docker run --rm -it -p 7000:7000 -v <PATH_TO_FILE>/pdc-portal.yml:/home/portal/config/pdc-portal.yml pdc-portal:my-tag
```

### Kubernetes

tbd

