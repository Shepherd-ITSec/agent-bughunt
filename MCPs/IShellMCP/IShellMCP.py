#!/usr/bin/env python3

import asyncio
import uuid
import time
import logging
import paramiko
from mcp.server.fastmcp import FastMCP

# Active SSH sessions
sessions = {}

class SSHSession:
    def __init__(self, client, channel):
        self.client = client
        self.channel = channel
        self.buffer = ""
        self.created = time.time()

    def write(self, command: str):
        self.channel.send(command + "\n")

    def read(self, timeout: float = 0.5) -> str:
        """Read data with a short wait"""
        end_time = time.time() + timeout
        output = ""
        while time.time() < end_time:
            if self.channel.recv_ready():
                data = self.channel.recv(4096).decode()
                output += data
            else:
                time.sleep(0.05)
        return output.strip()


mcp = FastMCP("i-ssh-mcp")


@mcp.tool()
async def ssh_open_session(host: str, username: str, password: str, port: int = 22):
    """Open a persistent SSH shell session"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password)

    channel = client.invoke_shell()
    session_id = str(uuid.uuid4())
    sessions[session_id] = SSHSession(client, channel)

    return f"Session opened with id: {session_id}"


@mcp.tool()
async def ssh_send(sessionId: str, command: str):
    """Send a command to an existing SSH session"""
    sess = sessions.get(sessionId)
    if not sess:
        return f"No session found for id: {sessionId}"

    sess.buffer = ""
    sess.write(command)
    output = sess.read()
    sess.buffer = output
    return output if output else "(no output)"


@mcp.tool()
async def ssh_status(sessionId: str):
    """Get the status of an SSH session"""
    sess = sessions.get(sessionId)
    if not sess:
        return f"No session found for id: {sessionId}"

    uptime = int(time.time() - sess.created)
    preview = sess.buffer.split("\n")[-5:]
    preview_text = "\n".join(preview).strip() or "(no recent output)"

    return f"Session {sessionId} is active.\nUptime: {uptime}s\nLast output:\n{preview_text}"

@mcp.tool()
async def list_sessions():
    """Get a list of all active SSH sessions"""
    return list(sessions.keys())
    



@mcp.tool()
async def ssh_close_session(sessionId: str):
    """Close an active SSH session"""
    sess = sessions.get(sessionId)
    if not sess:
        return f"No session found for id: {sessionId}"

    sess.client.close()
    del sessions[sessionId]
    return f"Session {sessionId} closed."


if __name__ == "__main__":
    # Initialize and run the server
    logging.info("Starting SSH MCP server...")
    mcp.run(transport='stdio')
