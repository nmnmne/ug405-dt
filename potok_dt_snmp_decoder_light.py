import asyncio
import ipaddress
import time
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

def parse_detectors_status(hex_string):
    """Парсит hex-строку и возвращает статусы детекторов"""
    if not hex_string or hex_string == "None" or not hex_string.startswith("0x"):
        return []
    
    # Очищаем строку от лишних пробелов и непечатаемых символов
    hex_string = ''.join(hex_string.split())
    hex_string = hex_string.strip()
    
    # Убираем префикс "0x"
    hex_data = hex_string[2:]
    
    # Делим строку на 4 равные части
    part_length = len(hex_data) // 4
    if part_length == 0:
        return []
    
    # Берем только первую часть
    first_part = hex_data[:part_length]
    
    # Каждый символ в первой части - это статус одного детектора
    detectors_status = list(first_part)
    
    return detectors_status

def reorder_detectors(detectors):
    """Переупорядочивает детекторы согласно правилу: 2,1,4,3,6,5 и т.д."""
    if not detectors:
        return []
    
    reordered = []
    for i in range(0, len(detectors), 2):
        if i + 1 < len(detectors):
            # Меняем местами пары: берем второй, затем первый
            reordered.append(detectors[i + 1])
            reordered.append(detectors[i])
        else:
            # Если нечетное количество, последний остается на месте
            reordered.append(detectors[i])
    
    return reordered

def get_emoji_status(status_char):
    """Возвращает эмодзи в зависимости от статуса детектора"""
    return "⚪" if status_char == '0' else "🟢"

def get_current_time_with_ms():
    """Возвращает текущее время с миллисекундами"""
    current_time = time.time()
    milliseconds = int((current_time - int(current_time)) * 1000)
    time_struct = time.localtime(current_time)
    return time.strftime("%H:%M:%S", time_struct) + f".{milliseconds:03d}"

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
        # Получаем статус детекторов
        oid_get = f".1.3.6.1.4.1.13267.3.2.5.1.1.32{old_str}"
        response = await snmp_get_request(ip_address, community_string, oid_get)
        return response
    
    return None

async def main():
    ip = "10.45.154.11"
    num_detectors = 0
    first_run = True
    
    while True:
        result = await get_ug405(ip)
        
        if result:
            # Получаем текущее время с миллисекундами
            current_time = get_current_time_with_ms()
            # Выводим сырые данные для отладки
            print(f"[{current_time}] Raw data: '{result}'")
            
            # Парсим статусы детекторов
            detectors = parse_detectors_status(result)
            
            # Если первый запуск, определяем количество детекторов
            if first_run and detectors:
                num_detectors = len(detectors)
                print(f"Обнаружено детекторов: {num_detectors}")
                first_run = False
            
            if detectors:
                # Переупорядочиваем детекторы
                reordered_detectors = reorder_detectors(detectors)
                
                # Формируем строку вывода с правильным форматированием
                output = f""
                detector_outputs = []
                
                for i, status in enumerate(reordered_detectors[:num_detectors], 1):
                    emoji = get_emoji_status(status)
                    # Используем форматирование с фиксированной шириной
                    detector_outputs.append(f"D{i:2d}={status}{emoji}")
                
                output += ", ".join(detector_outputs)
                print(output)
            else:
                current_time = get_current_time_with_ms()
                print(f"[{current_time}] Неверный формат данных")
        else:
            current_time = get_current_time_with_ms()
            print(f"[{current_time}] Нет данных от устройства")
        
        await asyncio.sleep(0.5)

if __name__ == "__main__":
    asyncio.run(main())