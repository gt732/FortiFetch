# FortiFetch
FortiFetch is a Python application that gathers information from FortiGate firewalls' API and saves the information to a SQLite3 database. FortiFetch is built using Python and the rich library for console output, and is designed to be easy to install, configure, and use.

## Installation

To install FortiFetch, follow these steps:

### Clone the FortiFetch repository from GitHub using the command 

```
git clone https://github.com/gt732/FortiFetch.git
```

Change into the FortiFetch directory using the command 

```
cd FortiFetch
```

### Create a new virtual environment using venv.

python -m venv fortifetch-env

- Activate the virtual environment.
source fortifetch-env/bin/activate

- Install FortiFetch using pip.
pip install fortifetch

### Set up the following environmental variables in your environment:

export FORTIFETCH_USERNAME=your_username
export FORTIFETCH_PASSWORD=your_password
export FORTIFETCH_INVENTORY=/your/path/inventory.yaml
export FORTIFETCH_SCHEME="http" or "https"

You can replace the values with your own FortiGate credentials and inventory file path. These environmental variables are used by FortiFetch to authenticate with your FortiGate devices and retrieve their information.

### Create an inventory file in YAML format with a list of your FortiGate devices, using the following format:

---
- hostname: example-hostname-1
  host: 192.168.0.1
- hostname: example-hostname-2
  host: 192.168.0.2
- hostname: example-hostname-3
  host: 192.168.0.3

Replace the values with your own FortiGate device hostnames and IP addresses. Save the file as inventory.yaml and provide its path as the value of FORTIFETCH_INVENTORY environmental variable.
## Usage
To use FortiFetch, you can run the following commands in your terminal:

fortifetch create-database: Creates a new SQLite3 database for FortiFetch.
fortifetch execute-sql: Executes a SQL command on the FortiFetch database.
fortifetch update-all-devices: Retrieves information about all FortiGate devices and saves it to the FortiFetch database.
fortifetch show-devices: Displays a table of all devices in the FortiFetch database.
fortifetch show-dns: Displays a table of DNS information for all devices in the FortiFetch database.
fortifetch show-vpn-status: Displays a table of VPN information for all devices in the FortiFetch database.
fortifetch show-interface: Displays a table of interface information for all devices in the FortiFetch database.
You can also use the --help flag with any command to see more detailed usage instructions.

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
If you have any questions or comments about FortiFetch, please feel free to contact us at our Github repository.