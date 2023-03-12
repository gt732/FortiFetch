from typer.testing import CliRunner
from fortifetch.main import app


def test_execute_sql():
    runner = CliRunner()
    result = runner.invoke(app, ["execute-sql", "SELECT * FROM device"])

    assert result.exit_code == 0
    assert "Device" in result.output
