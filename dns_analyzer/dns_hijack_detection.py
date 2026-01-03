import asyncio
import dns.message
import dns.rdatatype
from typing import Dict, Any

class DnsClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, query_data, on_response):
        self.query_data = query_data
        self.on_response = on_response

    def connection_made(self, transport):
        transport.sendto(self.query_data)

    def datagram_received(self, data, addr):
        if not self.on_response.done():
            self.on_response.set_result((data, addr))
            
    def error_received(self, exc):
        if not self.on_response.done():
            self.on_response.set_exception(exc)

async def check_dns_hijack(resolver_ip="8.8.8.8", domain="google.com") -> Dict[str, Any]:
    query = dns.message.make_query(domain, dns.rdatatype.A)
    loop = asyncio.get_running_loop()
    on_response = loop.create_future()
    
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DnsClientProtocol(query.to_wire(), on_response),
            remote_addr=(resolver_ip, 53)
        )
        data, addr = await asyncio.wait_for(on_response, timeout=3.0)
        responded_ip = addr[0]
        
        hijacked = responded_ip != resolver_ip
        warning = "Possible DNS interception detected." if hijacked else "Clean: No interception detected."
        
        return {
            "query_sent_to": resolver_ip,
            "response_received_from": responded_ip,
            "result": warning,
            "status": "warning" if hijacked else "safe"
        }
    except Exception as e:
        return {
            "query_sent_to": resolver_ip,
            "response_received_from": "None",
            "result": f"Test failed / Timeout: {str(e)}",
            "status": "error"
        }
    finally:
        try:
            transport.close()
        except:
            pass
