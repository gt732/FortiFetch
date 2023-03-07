# FortiFetch
![alt text](https://i.imgur.com/4NBl5Xm.png)

FortiFetch is a Python application that gathers information from FortiGate firewalls' API and saves the information to a Postgres database using the SQLAlchemy library. FortiFetch is built using the Typer/Rich library for console output, and is designed to be easy to install, configure, and use. The purpose of this app is to quickly take a live snapshot of the network for analysis and configuration verification.

## Tested on Fortigate VM version 7.2.4

Tables in Postgres database, check the sqlalchemy models file for complete column list.

- device
- interface
- firewallpolicy
- webprofile
- dnsprofile
- appprofile
- ipsprofile
- sslsshprofile
- avprofile
- address
- addressgroup
- internetservice
- ippool
- vip
- trafficshapers
- trafficpolicy
- dns
- staticroute
- policyroute
- snmpv2
- snmpv3
- fortiguard
- admin
- adminprofile
## Installation

To install FortiFetch, follow these steps:

## Docker

### Set up the following environmental variables in your environment:

```
export FORTIFETCH_SCHEME=http or https #changeme   
export FORTIFETCH_USERNAME=admin #changeme
export FORTIFETCH_PASSWORD=admin #changeme
export FORTIFETCH_INVENTORY=/path/to/your/inventory.yml
export FORTIFETCH_DB_HOSTNAME=postgres
export FORTIFETCH_DB_PORT=5432
export FORTIFETCH_DB_NAME=fortifetch
export FORTIFETCH_DB_USERNAME=postgres #changeme
export FORTIFETCH_DB_PASSWORD=admin123 #changeme
export FORTIFETCH_INVENTORY=/usr/src/app/fortifetch/inventory/inventory.yml
```

Create a base folder

```
mkdir your_folder
```
cd into your_folder, and create a docker-compose.yml file - copy the contents from the repo into your compose file

```
cd your_folder
touch docker-compose.yml
```

Create another folder called inventory and place your inventory.yml file inside the folder

```
mkdir inventory
```
Example inventory.yml
```
---
- hostname: example-hostname-1
  host: 192.168.0.1
- hostname: example-hostname-2
  host: 192.168.0.2
- hostname: example-hostname-3
  host: 192.168.0.3
```

Example dir

```
your_folder
├── docker-compose.yml
└── inventory
    └── inventory.yml
```

From the ROOT dir of your_folder run the docker compose command

```
docker compose up -d
```
Attach to the container and you are all set

```
docker exec -it fortifetch-fortifetch-1 bash
```
Inside the container run
```
python main.py --help
```

## Usage
To use FortiFetch, you can run the following commands in your terminal:

![alt text](https://i.imgur.com/ZaCOfrK.png)
![alt text](https://i.imgur.com/Dh0yanS.png)
![alt text](https://i.imgur.com/kK86tOD.png)
![alt text](https://i.imgur.com/ulfIxvC.png)
![alt text](https://i.imgur.com/CLbjH2F.png)
![alt text](https://i.imgur.com/lBosUC9.png)

## If a device is unable to connect you will see the following
![alt text](https://i.imgur.com/fstNDvc.png)
## Contributing
If you'd like to contribute to FortiFetch, please follow these steps:

Fork the FortiFetch repository.
Clone your fork to your local machine.
Create a new branch for your changes.
Make your changes and commit them.
Push your changes to your fork.
Create a pull request on the main FortiFetch repository.

## License
FortiFetch is licensed under the MIT license. See the LICENSE file for more information.

## Contact
If you have any questions or comments about FortiFetch, please feel free to contact me.