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

app = typer.Typer()


@app.command("create-database")
def create_sql_database():
    print("Creating database: FortiFetch.db")
    FortiFetch.create_sql_database()


@app.command("execute-sql")
def execute_sql(sql: str, params: Optional[str] = None):
    print(FortiFetch.execute_sql(sql, params))


@app.command("update-all-devices")
def update_all_devices():
    FortiFetch.update_all_devices()


@app.command("show-devices")
def show_devices():
    devices = FortiFetch.execute_sql("SELECT * FROM device")
    table = Table(
        show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
    )
    table.add_column("Hostname", style="bold")
    table.add_column("Serial Number", style="bold")
    table.add_column("Version", style="bold")
    table.add_column("Model", style="bold")
    for device in devices:
        table.add_row(
            device["hostname"],
            device["serial_number"],
            device["version"],
            device["model"],
            style="white",
        )
    console = Console()
    console.print(table)


@app.command("show-dns")
def show_dns(hostname: Optional[str] = None):
    if hostname:
        devices = FortiFetch.execute_sql(
            f"""
            SELECT device.hostname, dns.primary_dns, dns.secondary_dns
            FROM device
            JOIN dns ON device.device_id = dns.device_id
            WHERE device.hostname = '{hostname}'                                        
            """
        )
        table = Table(
            show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
        )
        table.add_column("Hostname", style="bold")
        table.add_column("Primary DNS", style="bold")
        table.add_column("Secondary DNS", style="bold")
        for device in devices:
            table.add_row(
                device["hostname"],
                device["primary_dns"],
                device["secondary_dns"],
                style="white",
            )
        console = Console()
        console.print(table)
    else:
        devices = FortiFetch.execute_sql(
            f"""
            SELECT device.hostname, dns.primary_dns, dns.secondary_dns
            FROM device
            JOIN dns ON device.device_id = dns.device_id                                        
            """
        )
        table = Table(
            show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
        )
        table.add_column("Hostname", style="bold")
        table.add_column("Primary DNS", style="bold")
        table.add_column("Secondary DNS", style="bold")
        for device in devices:
            table.add_row(
                device["hostname"],
                device["primary_dns"],
                device["secondary_dns"],
                style="white",
            )
        console = Console()
        console.print(table)


@app.command("show-vpn-status")
def show_vpn_status(hostname: Optional[str] = None):
    if hostname:
        devices = FortiFetch.execute_sql(
            f"""
            SELECT device.hostname , vpnmonitor.phase1_name , vpnmonitor.phase2_name , vpnmonitor.phase2_status 
            FROM device
            JOIN vpnmonitor
            WHERE device.hostname = '{hostname}'                            
            """
        )
        table = Table(
            show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
        )
        table.add_column("Hostname", style="bold")
        table.add_column("VPN Tunnel", style="bold")
        table.add_column("VPN Phase2", style="bold")
        table.add_column("VPN Status", style="bold")
        for device in devices:
            table.add_row(
                device["hostname"],
                device["phase1_name"],
                device["phase2_name"],
                device["phase2_status"],
                style="white",
            )
        console = Console()
        console.print(table)
    else:
        devices = FortiFetch.execute_sql(
            """
            SELECT device.hostname , vpnmonitor.phase1_name , vpnmonitor.phase2_name , vpnmonitor.phase2_status 
            FROM device
            JOIN vpnmonitor
            ON device.device_id = vpnmonitor.device_id                                
            """
        )
        table = Table(
            show_header=True, header_style="bold blue", box=box.HEAVY, show_lines=True
        )
        table.add_column("Hostname", style="bold")
        table.add_column("VPN Tunnel", style="bold")
        table.add_column("VPN Phase2", style="bold")
        table.add_column("VPN Status", style="bold")
        for device in devices:
            table.add_row(
                device["hostname"],
                device["phase1_name"],
                device["phase2_name"],
                device["phase2_status"],
                style="white",
            )
        console = Console()
        console.print(table)


@app.command("show-interface")
def show_interface(hostname: Optional[str] = None):
    if hostname:
        devices = FortiFetch.execute_sql(
            f"""
            SELECT device.hostname, interface.name , interface.type, interface.ip, interface.status
            FROM device
            JOIN interface
            ON device.device_id = interface.device_id
            WHERE device.hostname = '{hostname}'                              
            """
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
                device["hostname"],
                device["name"],
                device["type"],
                device["ip"],
                device["status"],
                style="white",
            )
        console = Console()
        console.print(table)
    else:
        devices = FortiFetch.execute_sql(
            """
            SELECT device.hostname, interface.name , interface.type, interface.ip, interface.status
            FROM device
            JOIN interface
            ON device.device_id = interface.device_id                               
            """
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
                device["hostname"],
                device["name"],
                device["type"],
                device["ip"],
                device["status"],
                style="white",
            )
        console = Console()
        console.print(table)


if __name__ == "__main__":
    app()
