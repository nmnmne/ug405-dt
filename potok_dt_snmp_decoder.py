import asyncio
import ipaddress
import time
import os
from datetime import datetime
from pysnmp.hlapi.asyncio import *

# Загрузка констант из .env
SCAN_MODE = os.getenv('SCAN_MODE', 'light').lower()  # 'light' или 'full'
IP_ADDRESS = os.getenv('IP', '10.179.72.97')
SKIP_DUPLICATES = os.getenv('SKIP_DUPLICATES', 'true').lower() == 'false'  # Пропуск повторяющихся 

# Создаем папку для логов
LOG_DIR = "logs_snmp"
os.makedirs(LOG_DIR, exist_ok=True)

# Таблица преобразования символов в бинарное представление (перевернутое)
CHAR_TO_BINARY = {
    '0': '0000',  # 0000 -> 0000
    '1': '1000',  # 0001 -> 1000
    '2': '0100',  # 0010 -> 0100
    '3': '1100',  # 0011 -> 1100
    '4': '0010',  # 0100 -> 0010
    '5': '1010',  # 0101 -> 1010
    '6': '0110',  # 0110 -> 0110
    '7': '1110',  # 0111 -> 1110
    '8': '0001',  # 1000 -> 0001
    '9': '1001',  # 1001 -> 1001
    'a': '0101',  # 1010 -> 0101
    'b': '1101',  # 1011 -> 1101
    'c': '0011',  # 1100 -> 0011
    'd': '1011',  # 1101 -> 1011
    'e': '0111',  # 1110 -> 0111
    'f': '1111',  # 1111 -> 1111
}

class DualLogger:
    def __init__(self):
        self.light_log_file = None
        self.full_log_file = None
        self.setup_log_files()
    
    def setup_log_files(self):
        """Создает два лог-файла с текущей датой для light и full режимов"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        
        # Файл для light режима
        self.light_log_file = os.path.join(LOG_DIR, f"snmp_log_light_{current_date}.txt")
        # Файл для full режима  
        self.full_log_file = os.path.join(LOG_DIR, f"snmp_log_full_{current_date}.txt")
        
        # Записываем заголовки при создании файлов
        for log_file, mode_name in [(self.light_log_file, "Light"), (self.full_log_file, "Full")]:
            if not os.path.exists(log_file):
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(f"SNMP Monitor Log - {current_date} ({mode_name} Mode)\n")
                    f.write(f"Scan Mode: {SCAN_MODE}\n")
                    f.write(f"IP Address: {IP_ADDRESS}\n")
                    f.write(f"Skip Duplicates: {SKIP_DUPLICATES}\n")
                    f.write("=" * 80 + "\n\n")
    
    def check_and_update_log_files(self):
        """Проверяет, не изменилась ли дата (для создания новых файлов)"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        expected_light_file = os.path.join(LOG_DIR, f"snmp_log_light_{current_date}.txt")
        expected_full_file = os.path.join(LOG_DIR, f"snmp_log_full_{current_date}.txt")
        
        if self.light_log_file != expected_light_file or self.full_log_file != expected_full_file:
            self.setup_log_files()
    
    def write_light_log(self, message):
        """Записывает сообщение в light лог-файл"""
        try:
            self.check_and_update_log_files()
            with open(self.light_log_file, 'a', encoding='utf-8') as f:
                f.write(message + '\n')
        except Exception as e:
            print(f"Ошибка записи в light лог: {e}")
    
    def write_full_log(self, message):
        """Записывает сообщение в full лог-файл"""
        try:
            self.check_and_update_log_files()
            with open(self.full_log_file, 'a', encoding='utf-8') as f:
                f.write(message + '\n')
        except Exception as e:
            print(f"Ошибка записи в full лог: {e}")
    
    def write_both_logs(self, light_message, full_message):
        """Записывает сообщения в оба лог-файла"""
        self.write_light_log(light_message)
        self.write_full_log(full_message)

# Глобальный объект логгера
logger = DualLogger()

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

def get_emoji_from_binary(bit):
    """Возвращает эмодзи в зависимости от бинарного значения"""
    return "⚪" if bit == '0' else "🟢"

def get_current_time_with_ms():
    """Возвращает текущее время с миллисекундами"""
    current_time = time.time()
    milliseconds = int((current_time - int(current_time)) * 1000)
    time_struct = time.localtime(current_time)
    return time.strftime("%H:%M:%S", time_struct) + f".{milliseconds:03d}"

def get_current_datetime():
    """Возвращает текущую дату и время для логов"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def convert_to_binary_representation(detectors):
    """Преобразует символы детекторов в бинарное представление (4 строки)"""
    if not detectors:
        return []
    
    binary_lines = []
    
    # Для каждого детектора получаем его бинарное представление
    for detector_char in detectors:
        char_lower = detector_char.lower()
        binary_repr = CHAR_TO_BINARY.get(char_lower, '0000')
        binary_lines.append(binary_repr)
    
    # Транспонируем: создаем 4 строки, каждая содержит соответствующий бит из каждого детектора
    result_lines = []
    for bit_position in range(4):
        line_bits = [line[bit_position] for line in binary_lines]
        result_lines.append(line_bits)
    
    return result_lines

def print_light_output(reordered_detectors, num_detectors):
    """Вывод в легком режиме"""
    detector_outputs = []
    for i, status in enumerate(reordered_detectors[:num_detectors], 1):
        emoji = get_emoji_status(status)
        detector_outputs.append(f"{emoji} {i}={status}")
    return " ".join(detector_outputs)

def print_full_output(reordered_detectors, num_detectors):
    """Вывод в полном режиме (4 строки с бинарным представлением)"""
    binary_lines = convert_to_binary_representation(reordered_detectors[:num_detectors])
    
    output_lines = []
    for line_idx, line_bits in enumerate(binary_lines):
        detector_outputs = []
        for i, bit in enumerate(line_bits, 1):
            emoji = get_emoji_from_binary(bit)
            # Получаем оригинальный символ для отображения
            original_char = reordered_detectors[i-1] if i-1 < len(reordered_detectors) else '0'
            detector_outputs.append(f"{emoji} {i}={original_char}")
        output_lines.append(" ".join(detector_outputs))
    
    return "\n".join(output_lines)

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
    ip = IP_ADDRESS
    num_detectors = 0
    first_run = True
    previous_raw_data = None
    
    print(f"Режим сканирования: {SCAN_MODE}")
    print(f"IP адрес: {ip}")
    print(f"Пропуск одинаковых ответов: {'ВКЛЮЧЕН' if SKIP_DUPLICATES else 'ВЫКЛЮЧЕН'}")
    print(f"Логи сохраняются в папку: {LOG_DIR}")
    print(f"Созданы два лог-файла: light и full режимы")
    
    # Логируем начало работы в оба файла
    start_message = f"[{get_current_datetime()}] Запуск мониторинга"
    logger.write_both_logs(start_message, start_message)
    
    mode_message = f"[{get_current_datetime()}] Режим сканирования: {SCAN_MODE}"
    logger.write_both_logs(mode_message, mode_message)
    
    ip_message = f"[{get_current_datetime()}] IP адрес: {ip}"
    logger.write_both_logs(ip_message, ip_message)
    
    skip_message = f"[{get_current_datetime()}] Пропуск одинаковых ответов: {'ВКЛЮЧЕН' if SKIP_DUPLICATES else 'ВЫКЛЮЧЕН'}"
    logger.write_both_logs(skip_message, skip_message)
    
    while True:
        result = await get_ug405(ip)
        
        if result:
            # Проверяем, нужно ли пропускать одинаковые ответы
            if SKIP_DUPLICATES and result == previous_raw_data:
                # Данные повторяются и пропуск включен - не выводим
                current_time = get_current_time_with_ms()
                # print(f"[{current_time}] 🟡 Данные не изменились, пропускаем вывод")
                pass  # Полностью пропускаем вывод
            else:
                # Данные новые или пропуск выключен - выводим как обычно
                current_time = get_current_time_with_ms()
                current_datetime = get_current_datetime()
                
                # Добавляем отметку о дубликате, если это повторяющиеся данные при выключенном пропуске
                duplicate_marker = "" if not SKIP_DUPLICATES and result == previous_raw_data else ""
                
                terminal_message = f"[{current_time}] Raw data: '{result}'{duplicate_marker}"
                log_message = f"[{current_datetime}] Raw data: '{result}'{duplicate_marker}"
                
                print(terminal_message)
                # Сырые данные пишем в оба лога
                logger.write_both_logs(log_message, log_message)
                
                # Парсим статусы детекторов
                detectors = parse_detectors_status(result)
                
                # Если первый запуск, определяем количество детекторов
                if first_run and detectors:
                    num_detectors = len(detectors)
                    detectors_message = f"Обнаружено детекторов: {num_detectors}"
                    print(detectors_message)
                    logger.write_both_logs(
                        f"[{get_current_datetime()}] {detectors_message}", 
                        f"[{get_current_datetime()}] {detectors_message}"
                    )
                    first_run = False
                
                if detectors:
                    # Переупорядочиваем детекторы
                    reordered_detectors = reorder_detectors(detectors)
                    
                    # Генерируем вывод для обоих режимов
                    light_output = print_light_output(reordered_detectors, num_detectors)
                    full_output = print_full_output(reordered_detectors, num_detectors)
                    
                    # Выводим в терминал в зависимости от текущего режима
                    if SCAN_MODE == 'light':
                        print(light_output)
                    else:  # full mode
                        print(full_output)
                    
                    # Логируем в соответствующие файлы
                    logger.write_light_log(f"[{current_datetime}] {light_output}")
                    
                    # Для полного режима логируем каждую строку отдельно
                    for line in full_output.split('\n'):
                        logger.write_full_log(f"[{current_datetime}] {line}")
                        
                else:
                    error_message = "Неверный формат данных"
                    print(f"[{current_time}] {error_message}")
                    logger.write_both_logs(
                        f"[{current_datetime}] {error_message}", 
                        f"[{current_datetime}] {error_message}"
                    )
                
                # Сохраняем текущие данные как предыдущие
                previous_raw_data = result
                
        else:
            current_time = get_current_time_with_ms()
            current_datetime = get_current_datetime()
            error_message = "Нет данных от устройства"
            print(f"[{current_time}] {error_message}")
            logger.write_both_logs(
                f"[{current_datetime}] {error_message}", 
                f"[{current_datetime}] {error_message}"
            )

        await asyncio.sleep(0.2)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nМониторинг остановлен пользователем")
        stop_message = f"[{get_current_datetime()}] Мониторинг остановлен пользователем"
        logger.write_both_logs(stop_message, stop_message)
    except Exception as e:
        error_msg = f"Критическая ошибка: {e}"
        print(error_msg)
        logger.write_both_logs(
            f"[{get_current_datetime()}] {error_msg}", 
            f"[{get_current_datetime()}] {error_msg}"
        )
