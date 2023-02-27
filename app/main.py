"""
This Main module is the entry point of the application. It contains a list of
commands which can be run from the command line.
"""


# import modules
import typer
from rich import print
from rich.console import Console
from rich.table import Table
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
    table = Table(show_header=True, header_style="bold yellow")
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
            style="green",
        )
    console = Console()
    console.print(table)


if __name__ == "__main__":
    app()
