#!/usr/bin/env python3
import json
import sys
import os
from dotenv import load_dotenv
import asyncio
import logging
import pyodbc
from mcp.server import Server
from mcp.types import Resource, Tool, TextContent
from pydantic import AnyUrl
import re
import urllib.parse

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mssql_mcp_server")

app = Server("mssql_mcp_server")

class DBConfig:
    def __init__(self):
        self.config = {
            "server": os.getenv("MSSQL_SERVER"),
            "database": os.getenv("MSSQL_DATABASE"), 
            "user": os.getenv("MSSQL_USER"),
            "password": os.getenv("MSSQL_PASSWORD"),
            "driver": os.getenv("MSSQL_DRIVER")
        }
        self.connection = None

    def get_connection(self):
        try:
            if not self.connection:
                logger.info("Attempting to establish new database connection")
                conn_str = (
                    f"DRIVER={self.config['driver']};"
                    f"SERVER={self.config['server']};"
                    f"DATABASE={self.config['database']};"
                    f"UID={self.config['user']};"
                    f"PWD={self.config['password']};"
                    "TrustServerCertificate=yes"
                )
                self.connection = pyodbc.connect(conn_str, readonly=True)  # add readonly=True
                logger.info("Database connection established successfully")
            return self.connection
        except Exception as e:
            logger.error(f"Failed to establish database connection: {str(e)}")
            self.connection = None
            raise

class SQLValidator:
    @staticmethod
    def is_read_only_query(query: str) -> bool:
        logger.info(f"Validating query: {query}")
        # Clean the query
        clean_query = query.strip().upper()
        
        # List of allowed statements
        allowed_statements = [
            'SELECT', 'WITH', 'DECLARE'
        ]
        
        # List of forbidden statements
        forbidden_statements = [
            'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 
            'ALTER', 'TRUNCATE', 'MERGE', 'UPSERT', 'REPLACE',
            'GRANT', 'REVOKE', 'EXEC', 'EXECUTE', 'SP_'
        ]
        
        # Check if it starts with an allowed statement
        starts_with_allowed = any(clean_query.startswith(stmt) for stmt in allowed_statements)
        if not starts_with_allowed:
            logger.warning(f"Query rejected: Does not start with allowed statement")
            return False
            
        # Check if it contains any forbidden statements
        contains_forbidden = any(stmt in clean_query for stmt in forbidden_statements)
        if contains_forbidden:
            logger.warning(f"Query rejected: Contains forbidden statement")
            return False
            
        # Additional check for SQL Injection
        has_dangerous_chars = re.search(r';\s*\w+', clean_query)  # Look for semicolons followed by commands
        if has_dangerous_chars:
            logger.warning(f"Query rejected: Potential SQL injection detected")
            return False
            
        logger.info("Query validation successful")
        return True

db = DBConfig()
sql_validator = SQLValidator()

@app.list_resources()
async def list_resources() -> list[Resource]:
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        tables = cursor.execute(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'"
        ).fetchall()
        
        return [
            Resource(
                uri=f"mssql://{urllib.parse.quote(table[0])}/data",
                name=f"Table: {table[0]}",
                mimeType="application/json",
                description=f"Data in table {table[0]}"
            )
            for table in tables
        ]
    except Exception as e:
        logger.error(f"Failed to list resources: {str(e)}")
        return []

@app.read_resource()
async def read_resource(uri: AnyUrl) -> str:
    logger.info(f"Resource access attempt for URI: {uri}")
    uri_str = str(uri)
    if not uri_str.startswith("mssql://"):
        raise ValueError(f"Invalid URI scheme: {uri_str}")
        
    encoded_table = uri_str[8:].split('/')[0]
    table = urllib.parse.unquote(encoded_table)
    query = f"SELECT TOP 100 * FROM {table}"
    
    if not sql_validator.is_read_only_query(query):
        raise ValueError("Only SELECT queries are allowed")
        
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        result = [",".join(map(str, row)) for row in rows]
        return "\n".join([",".join(columns)] + result)
    except Exception as e:
        logger.error(f"Error reading table {table}: {str(e)}")
        raise RuntimeError(f"Database error: {str(e)}")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="execute_sql",
            description="Execute a READ-ONLY SQL query (SELECT only)",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "SQL SELECT query to execute"}
                },
                "required": ["query"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    logger.info(f"Tool execution request: {name} with arguments: {arguments}")
    if name != "execute_sql":
        raise ValueError(f"Unknown tool: {name}")

    query = arguments.get("query")
    if not query:
        raise ValueError("Query is required")

    # Check if it's a read-only query
    if not sql_validator.is_read_only_query(query):
        return [TextContent(type="text", text="Error: Only SELECT queries are allowed")]

    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        result = [",".join(map(str, row)) for row in rows]
        logger.info(f"Query executed successfully, returned {len(rows)} rows")
        return [TextContent(type="text", text="\n".join([",".join(columns)] + result))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def main():
    logger.info("Starting MSSQL MCP server")
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
