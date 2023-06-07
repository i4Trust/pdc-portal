# pdc-portal

Packet Delivery Portal application for i4Trust experimentation framework 

## Configuration

Configuration is done in the file `config/pdc-portal.yml`. You need to modify the values according to your 
environment and add your private key and certificate chain.

Private key and certificate chain can be also provided as ENVs as given below. In this case, the values from 
`config/pdc-portal.yml` would be overwritten.
* Private key: `PORTAL_CLIENT_KEY`
* Certificate chain: `PORTAL_CLIENT_CRT`


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

A Helm chart is provided on [GitHub](https://github.com/i4Trust/helm-charts/tree/main/charts/pdc-portal) 
and [Artifacthub](https://artifacthub.io/packages/helm/i4trust/pdc-portal).



## Debug

Enable debugging by setting the environment variable:
```shell
DEBUG="portal:*"
```


