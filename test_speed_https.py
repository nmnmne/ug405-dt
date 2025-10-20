import requests
import time
import urllib3
urllib3.disable_warnings()

def test_https_speed(ip):
    session = requests.Session()
    session.verify = False
    
    print(f"🔍 ТЕСТ HTTPS: {ip}")
    print("=" * 30)
    
    times = []
    
    for i in range(10):
        start = time.time()
        try:
            response = session.get(f"https://{ip}/", timeout=5)
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)
            print(f"Запрос {i+1}: {elapsed:.1f}мс")
            
            # Сохраняем первую страницу в файл
            if i == 0:
                filename = f"{ip}_page.html"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                print(f"Страница сохранена в: {filename}")
                
        except Exception as e:
            print(f"Запрос {i+1}: ОШИБКА - {e}")
            return
    
    if times:
        print("=" * 30)
        print(f"Мин: {min(times):.1f}мс")
        print(f"Макс: {max(times):.1f}мс")
        print(f"Сред: {sum(times)/len(times):.1f}мс")

test_https_speed("10.45.154.11")