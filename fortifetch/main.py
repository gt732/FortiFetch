"""
This Main module is the entry point of the application. It contains a list of
commands which can be run from the command line.
"""


# import modules
import typer
from rich import print
from rich.console import Console
from rich.table import Table
from rich import box
from fortifetch.fortifetch import FortiFetch
from typing import List, Dict, Optional
from db.db import get_db
from db.models import *

app = typer.Typer()


@app.command("execute-sql")
def execute_sql(sql: str, params: Optional[str] = None):
    """
    Executes an SQL query on the 'FortiFetch' database.

    Usage: execute-sql SQL [PARAMS]

    This command takes an SQL query string and optional query parameters as input,
    and then executes the query on the 'FortiFetch' SQL database.

    Arguments:
    - sql: A string representing an SQL query to be executed.
    - params: An optional string representing query parameters to be used in the query.

    Example:
    execute-sql "SELECT * FROM device"

    """
    print(FortiFetch.execute_sql(sql, params))


@app.command("update-all-devices")
def update_all_devices():
    """
    Updates information for all devices/endpoints in the 'FortiFetch' database.

    Usage: update-all-devices

    This command calls all of the update methods in the FortiFetch library to
    update information for all devices/API endpoints in the 'FortiFetch' database.

    """
    FortiFetch.update_all_devices()


@app.command("show-devices")
def show_devices():
    """
    Displays a table of devices stored in the 'FortiFetch' database.

    Usage: show-devices

    This function retrieves information for all devices stored in the 'FortiFetch'
    SQL database and displays it in a table using the rich library. The table
    includes columns for hostname, serial number, firmware version, and device model.

    """
    with get_db() as db:
        devices = db.query(Device).all()

        table = Table(
            show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
        )
        table.add_column("Hostname", style="bold")
        table.add_column("Model", style="bold")
        table.add_column("Version", style="bold")

        for device in devices:
            table.add_row(
                device.hostname,
                device.model,
                device.version,
                style="white",
            )

        console = Console()
        console.print(table)


@app.command("show-dns")
def show_dns(hostname: Optional[str] = None):
    """
    Displays a table of DNS information for devices stored in the 'FortiFetch' database.

    Usage: show-dns [HOSTNAME]

    This function retrieves DNS information for all devices stored in the 'FortiFetch'
    SQL database, or for a specific device if the 'hostname' argument is provided.
    The function then displays the DNS information in a table using the rich library.
    The table includes columns for hostname, primary DNS, and secondary DNS.

    Arguments:
    - hostname (optional): A string representing the hostname of the device to show
      DNS information for. If provided, only the DNS information for that device will be displayed.

    """
    with get_db() as db:
        if hostname:
            devices = (
                db.query(Device.hostname, DNS.primary_dns, DNS.secondary_dns)
                .filter(Device.hostname == hostname)
                .join(DNS)
                .all()
            )
        else:
            devices = (
                db.query(Device.hostname, DNS.primary_dns, DNS.secondary_dns)
                .join(DNS)
                .all()
            )

        table = Table(
            show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
        )
        table.add_column("Hostname", style="bold")
        table.add_column("Primary DNS", style="bold")
        table.add_column("Secondary DNS", style="bold")
        for device in devices:
            table.add_row(
                device.hostname, device.primary_dns, device.secondary_dns, style="white"
            )
        console = Console()
        console.print(table)


@app.command("show-vpn-status")
def show_vpn_status(hostname: Optional[str] = None):
    """
    Displays a table of VPN information for devices stored in the 'FortiFetch' database.

    Usage: show-vpn-status [HOSTNAME]

    This function retrieves VPN information for all devices stored in the 'FortiFetch'
    SQL database, or for a specific device if the 'hostname' argument is provided.
    The function then displays the VPN information in a table using the rich library.
    The table includes columns for hostname, VPN tunnel name, VPN phase 2 name, and VPN status.

    Arguments:
    - hostname (optional): A string representing the hostname of the device to show
      VPN information for. If provided, only the VPN information for that device will be displayed.

    """
    with get_db() as db:
        query = db.query(
            Device.hostname,
            VpnMonitor.phase1_name,
            VpnMonitor.phase2_name,
            VpnMonitor.phase2_status,
        ).join(VpnMonitor, Device.device_id == VpnMonitor.device_id)
        if hostname:
            query = query.filter(Device.hostname == hostname)
        devices = query.all()
        table = Table(
            show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
        )
        table.add_column("Hostname", style="bold")
        table.add_column("VPN Tunnel", style="bold")
        table.add_column("VPN Phase2", style="bold")
        table.add_column("VPN Status", style="bold")
        for device in devices:
            table.add_row(
                device.hostname,
                device.phase1_name,
                device.phase2_name,
                device.phase2_status,
                style="white",
            )
        console = Console()
        console.print(table)


@app.command("show-interface")
def show_interface(hostname: Optional[str] = None):
    """
    Displays a table of interface information for devices stored in the 'FortiFetch' database.

    Usage: show-interface [HOSTNAME]

    This function retrieves interface information for all devices stored in the 'FortiFetch'
    SQL database, or for a specific device if the 'hostname' argument is provided.
    The function then displays the interface information in a table using the rich library.
    The table includes columns for hostname, interface name, interface type, interface IP, and interface status.

    Arguments:
    - hostname (optional): A string representing the hostname of the device to show
      interface information for. If provided, only the interface information for that device will be displayed.

    """
    with get_db() as db:
        if hostname:
            devices = (
                db.query(
                    Device.hostname,
                    Interface.name,
                    Interface.type,
                    Interface.ip,
                    Interface.status,
                )
                .filter(Device.hostname == hostname)
                .join(Interface)
                .all()
            )
        else:
            devices = (
                db.query(
                    Device.hostname,
                    Interface.name,
                    Interface.type,
                    Interface.ip,
                    Interface.status,
                )
                .join(Interface)
                .all()
            )
        table = Table(
            show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
        )
        table.add_column("Hostname", style="bold")
        table.add_column("Interface Name", style="bold")
        table.add_column("Interface Type", style="bold")
        table.add_column("Interface IP", style="bold")
        table.add_column("Interface Status", style="bold")
        for device in devices:
            table.add_row(
                device.hostname,
                device.name,
                device.type,
                device.ip,
                device.status,
                style="white",
            )
        console = Console()
        console.print(table)


if __name__ == "__main__":
    app()
