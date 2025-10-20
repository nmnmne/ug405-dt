import asyncio
import ipaddress
from pysnmp.hlapi.asyncio import *

async def snmp_get_request(ip, community, oid):
    """Асинхронный SNMP GET запрос"""
    error_indication, error_status, error_index, var_binds = await getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=True,
    )

    if error_indication:
        return None
    if error_status:
        return None

    for name, val in var_binds:
        return val.prettyPrint()

async def snmp_get_next_request(ip, community, oid):
    """Асинхронный SNMP GET NEXT запрос"""
    error_indication, error_status, error_index, var_binds = await nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=True,
    )

    if error_indication:
        return None
    if error_status:
        return None

    # Извлекаем SCN
    co = var_binds[0][0][1].prettyPrint()
    len_scn = str(len(co)) + "."
    scn = [str(ord(c)) for c in co]
    scn = ".".join(scn)
    scn = f".1.{len_scn}{scn}"
    return scn

async def get_ug405(ip_address):
    try:
        ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        return "Invalid IP Address"

    community_string = "UTMC"
    oid_get_request = ".1.3.6.1.4.1.13267.3.2.4.2.1.15"

    # Получаем SCN
    old_str = await snmp_get_next_request(ip_address, community_string, oid_get_request)

    if old_str is not None:
        # Получаем скут детекторов
        oid_get = f".1.3.6.1.4.1.13267.3.2.5.1.1.32{old_str}"
        responce = await snmp_get_request(ip_address, community_string, oid_get)

    return responce

async def main():
    ip = "10.45.154.11"
    while True:
        result = await get_ug405(ip)
        print(result)
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    asyncio.run(main())
