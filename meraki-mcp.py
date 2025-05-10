import os
import json
import meraki
import asyncio
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Create an MCP server
mcp = FastMCP("Meraki Magic MCP")

# Configuration
MERAKI_API_KEY = os.getenv("MERAKI_API_KEY")
MERAKI_ORG_ID = os.getenv("MERAKI_ORG_ID")

# Initialize Meraki API client using Meraki SDK
dashboard = meraki.DashboardAPI(api_key=MERAKI_API_KEY, suppress_logging=True)

# Create network in Meraki
@mcp.tool()
def create_network(name: str, tags: list[str], productTypes: list[str], copyFromNetworkId: str = None) -> str:
    """Create a new network in Meraki, optionally copying from another network."""
    kwargs = {}
    if copyFromNetworkId:
        kwargs['copyFromNetworkId'] = copyFromNetworkId
    network = dashboard.organizations.createOrganizationNetwork(MERAKI_ORG_ID, name, productTypes, tags=tags, **kwargs)
    return json.dumps(network, indent=2)

# Delete network in Meraki
@mcp.tool()
def delete_network(network_id: str) -> str:
    """Delete a network in Meraki"""
    dashboard.networks.deleteNetwork(network_id)
    return f"Network {network_id} deleted"


# Get networks from Meraki
@mcp.tool()
def get_networks() -> str:
    """Get a list of networks from Meraki"""
    networks = dashboard.organizations.getOrganizationNetworks(MERAKI_ORG_ID)
    return json.dumps(networks, indent=2)

# Get devices from Meraki
@mcp.tool()
def get_devices() -> str:
    """Get a list of devices from Meraki"""
    devices = dashboard.organizations.getOrganizationDevices(MERAKI_ORG_ID)
    return json.dumps(devices, indent=2)

# Get clients from Meraki
@mcp.tool()
def get_clients(network_id: str) -> str:
    """
    Get a list of clients from a specific Meraki network.

    Args:
        network_id (str): The ID of the Meraki network.

    Returns:
        str: JSON-formatted list of clients.
    """
    clients = dashboard.networks.getNetworkClients(network_id)
    return json.dumps(clients, indent=2)

# Get client policies from Meraki
@mcp.tool()
async def get_client_policy(network_id: str, client_id: str) -> str:
    """
    Get the policy for a specific client in a specific Meraki network.

    Args:
        network_id (str): The ID of the Meraki network.
        client_id (str): The ID (MAC address or client ID) of the client.

    Returns:
        str: JSON-formatted client policy.
    """
    loop = asyncio.get_event_loop()
    policy = await loop.run_in_executor(
        None,
        lambda: dashboard.networks.getNetworkClientPolicy(network_id, client_id)
    )
    return json.dumps(policy, indent=2)

# Define resources
#Add a dynamic greeting resource
@mcp.resource("greeting: //{name}")
def greeting(name: str) -> str:
    """Greet a user by name"""
    return f"Hello {name}!"
    
#execute and return the stdio output
if __name__ == "__main__":
    mcp.run()