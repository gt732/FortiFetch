"""
This Main module is the entry point of the application. It contains a list of
commands which can be run from the command line.
"""


# import modules
import typer
from rich import print
from fortifetch.fortifetch import FortiFetch


app = typer.Typer()


@app.command("create-database")
def create_sql_database():
    print("Creating database: FortiFetch.db")
    FortiFetch.create_sql_database()


@app.command("update-all-devices")
def update_all_devices():
    FortiFetch.update_all_devices()


if __name__ == "__main__":
    app()
