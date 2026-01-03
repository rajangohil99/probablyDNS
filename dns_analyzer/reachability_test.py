import asyncio
import platform
from typing import Dict, Any, List

async def ping(ip: str) -> bool:
    try:
        param = '-n' if platform.system().lower()=='windows' else '-c'
        timeout = '1000' if platform.system().lower()=='windows' else '1'
        if platform.system().lower()=='windows':
            command = ['ping', param, '1', '-w', timeout, ip]
        else:
            command = ['ping', param, '1', '-W', timeout, ip]
            
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()
        return proc.returncode == 0
    except Exception:
        return False

async def check_tcp(ip: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def test_reachability(ips: List[str]) -> Dict[str, Any]:
    """Verify routing and ICMP/TCP reachability from current environment."""
    if not ips:
        return {"status": "error", "message": "No IP resolved to test reachability"}
        
    ip = ips[0]
    
    ping_res, tcp_80, tcp_443 = await asyncio.gather(
        ping(ip), check_tcp(ip, 80), check_tcp(ip, 443)
    )
    
    return {
        "ip": ip,
        "ping": "successful" if ping_res else "timeout",
        "tcp_80": "open" if tcp_80 else "timeout/closed",
        "tcp_443": "open" if tcp_443 else "timeout/closed",
        "is_reachable": ping_res or tcp_80 or tcp_443
    }
