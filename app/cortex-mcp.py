from fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import Optional
from dotenv import load_dotenv
import ipaddress
import re
import os
import httpx
import asyncio

load_dotenv()

app = FastMCP("cortex-analysis")

CORTEX_URL = os.getenv("CORTEX_URL", "http://localhost:9001")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "")
ABUSEIPDB_ANALYZER_ID = os.getenv("ABUSEIPDB_ANALYZER_ID", "")
VIRUSTOTAL_ANALYZER_ID = os.getenv("VIRUSTOTAL_ANALYZER_ID", "")
URLSCAN_ANALYZER_ID = os.getenv("URLSCAN_ANALYZER_ID", "")

class AnalyzeParams(BaseModel):
    input_value: str = Field(..., description="IP, domain/FQDN, or hash to analyze.")
    analyzer_id: Optional[str] = Field(
        None, description="Optional: override analyzer ID."
    )
    max_retries: Optional[int] = Field(
        None, description="Maximum polling retries (default 5)."
    )

def detect_type(value: str) -> str:
    v = value.strip()
    if not v:
        raise ValueError("Input cannot be empty")

    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    domain_pattern = re.compile(
        r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$"
    )
    if domain_pattern.match(v):
        return "fqdn"

    if re.fullmatch(r"[A-Fa-f0-9]{32}", v) or \
       re.fullmatch(r"[A-Fa-f0-9]{40}", v) or \
       re.fullmatch(r"[A-Fa-f0-9]{64}", v):
        return "hash"

    raise ValueError("Not a valid IP, FQDN, or supported hash.")

async def run_analyzer_by_id(
    analyzer_id: str,
    value: str,
    max_retries: int = 5,
):
    headers = {
        "Authorization": f"Bearer {CORTEX_API_KEY}",
        "Content-Type": "application/json",
    }
    dtype = detect_type(value)
    payload = {
        "data": value,
        "dataType": dtype,
        "tlp": 0,
        "message": f"MCP Cortex: Analyzing {dtype} {value} with {analyzer_id}",
        "label": f"mcp_analysis_{value}",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(f"{CORTEX_URL}/api/analyzer/{analyzer_id}/run",
                              headers=headers, json=payload)
        r.raise_for_status()
        job_id = r.json().get("id")
        if not job_id:
            raise RuntimeError("Failed to create analyzer job.")

        for _ in range(max_retries):
            await asyncio.sleep(3)
            rep = await client.get(f"{CORTEX_URL}/api/job/{job_id}/report", headers=headers)
            if rep.status_code == 200:
                data = rep.json()
                if data.get("status") in ("Success", "Completed"):
                    return data

    raise RuntimeError("Analyzer job did not complete in time")

# Tools 
@app.tool()
async def analyze_with_abuseipdb(params: AnalyzeParams):
    """Analyze input with AbuseIPDB (mostly IPs)."""
    try:
        dtype = detect_type(params.input_value)
        analyzer_id = params.analyzer_id or ABUSEIPDB_ANALYZER_ID
        report = await run_analyzer_by_id(analyzer_id, params.input_value, params.max_retries or 5)
        return {"input": params.input_value, "data_type": dtype, "analyzer_id": analyzer_id, "report": report}
    except Exception as e:
        return {"error": str(e)}

@app.tool()
async def analyze_with_virustotal(params: AnalyzeParams):
    """Analyze input with VirusTotal (IP, domain/FQDN, hash)."""
    try:
        dtype = detect_type(params.input_value)
        analyzer_id = params.analyzer_id or VIRUSTOTAL_ANALYZER_ID
        report = await run_analyzer_by_id(analyzer_id, params.input_value, params.max_retries or 5)
        return {"input": params.input_value, "data_type": dtype, "analyzer_id": analyzer_id, "report": report}
    except Exception as e:
        return {"error": str(e)}

@app.tool()
async def analyze_with_urlscan(params: AnalyzeParams):
    """Analyze domains/URLs with urlscan.io analyzer."""
    try:
        dtype = detect_type(params.input_value)
        analyzer_id = params.analyzer_id or URLSCAN_ANALYZER_ID
        report = await run_analyzer_by_id(analyzer_id, params.input_value, params.max_retries or 5)
        return {"input": params.input_value, "data_type": dtype, "analyzer_id": analyzer_id, "report": report}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    app.run()
