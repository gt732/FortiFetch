"""
This module contains all the general backend functions to create and interact with the database.
"""

from typing import Union, Dict, Optional, List
from db.db import get_db


def execute_sql(sql: str, params: Optional[tuple] = None) -> List[Dict]:
    """
    Execute an SQL query and return the results.

    Args:
        sql: The SQL query to execute.
        params: The parameters to pass to the SQL query.

    Returns:
        A list of dictionaries containing the results of the query.
    """
    with get_db() as db:
        result = db.execute(sql, params)
        return [dict(row) for row in result]
