# import modules
import typer
from rich import print
from app.backend import db


app = typer.Typer()


@app.command("create-database")
def create_sql_database():
    print("Creating database: FortiFetch.db")
    db.create_database()


@app.command("update-devices")
def create():
    print("Creating user: Hiro Hamada")


@app.command()
def delete():
    print("Deleting user: Hiro Hamada")


if __name__ == "__main__":
    app()
