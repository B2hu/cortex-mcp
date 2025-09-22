# Cortex MCP Server

> [!CAUTION]
>
> **WARNING: this MCP server is EXPERIMENTAL.**.

Connect to Cortex analyzers directly from any MCP Client using the Model Context Protocol (MCP).

This server connects agents to your Cortex Analyzers using the Model Context Protocol. It allows you to interact and Search for known IOCs with your Analyzers through natural language conversations.

## Available Tools

* `analyze_with_abuseipdb`: Perform a Threat Intiligence For IP Addresses
* `analyze_with_virustotal`: Analyze input with VirusTotal (IP, domain/FQDN, hash).
* `analyze_with_urlscan`: PAnalyze domains/URLs with urlscan.io analyzer.

## Prerequisites

* A Cortex instance
* Cortex authentication credentials (API key)
* The Above Analyzers IDs.
* An MCP Client (e.g. [Claude Desktop](https://claude.ai/download), [Goose](https://block.github.io/goose/))


## Installation & Setup

This MCP server is provided as a Docker image,
that only supports MCP's stdio.

```
docker pull b2hu/cortex-mcp:v1
```

### Using the stdio protocol
before begining copy the .env.template to .env and paste you variables.

The MCP server needs environment variables to be set:

* you just need `.env` file.

The MCP server is started in stdio mode with this command:

```bash
docker run -i --rm --env-file .env b2hu/cortex-mcp:v1
```
The configuration for VSCode Copilot is as follows:
first run
```shell
mkdir .vscode
touch ./.vscode/mcp.json
```
```json
{
  "servers": {
    "cortex-mcp": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--env-file", ".env",
        "b2hu/cortex-mcp:v1"
      ]
    }
  }
}
```
