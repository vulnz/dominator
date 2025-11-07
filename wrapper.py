#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Vulnerability Scanner Wrapper
Wrapper script for monitoring and controlling the main scanner
"""

import subprocess
import sys
import signal
import os
import time
import threading
from datetime import datetime

class ScannerWrapper:
    """Wrapper class for monitoring and controlling the scanner"""
    
    def __init__(self):
        self.process = None
        self.start_time = None
        self.monitoring = False
        self.output_lines = []
        
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C signal for immediate termination"""
        print(f"\n[WRAPPER] Получен сигнал прерывания (Ctrl+C) в {datetime.now().strftime('%H:%M:%S')}")
        print("[WRAPPER] Принудительно завершаем дочерний процесс...")
        
        if self.process:
            try:
                # Попытка корректного завершения
                self.process.terminate()
                
                # Ждем 2 секунды для корректного завершения
                try:
                    self.process.wait(timeout=2)
                    print("[WRAPPER] Docherniy process zavershen korrektno")
                except subprocess.TimeoutExpired:
                    # Принудительное завершение если не завершился за 2 секунды
                    print("[WRAPPER] Prinuditel'noe zavershenie docherniego processa...")
                    self.process.kill()
                    self.process.wait()
                    print("[WRAPPER] Docherniy process prinuditel'no zavershen")
                    
            except Exception as e:
                print(f"[WRAPPER] Oshibka pri zavershenii processa: {e}")
        
        self.monitoring = False
        print("[WRAPPER] Vykhod iz programmy")
        sys.exit(0)
    
    def monitor_output(self):
        """Monitor process output in real-time"""
        if not self.process:
            return
            
        try:
            while self.monitoring and self.process.poll() is None:
                line = self.process.stdout.readline()
                if line:
                    line_str = line.decode('utf-8', errors='replace').rstrip()
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"[{timestamp}] {line_str}")
                    self.output_lines.append(f"[{timestamp}] {line_str}")
                    sys.stdout.flush()
                else:
                    time.sleep(0.1)
                    
        except Exception as e:
            if self.monitoring:  # Только показываем ошибку если мониторинг еще активен
                print(f"[WRAPPER] Oshibka monitoringa vyvoda: {e}")
    
    def print_status(self):
        """Print current status periodically"""
        while self.monitoring and self.process and self.process.poll() is None:
            elapsed = time.time() - self.start_time
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            
            # Показываем статус каждые 30 секунд
            if int(elapsed) % 30 == 0 and int(elapsed) > 0:
                print(f"[WRAPPER] Skanirovanie vypolnyaetsya: {minutes:02d}:{seconds:02d}")
                
            time.sleep(1)
    
    def run_scanner(self, args):
        """Run the main scanner with monitoring"""
        print("[WRAPPER] Zapusk Web Vulnerability Scanner")
        print(f"[WRAPPER] Vremya zapuska: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[WRAPPER] Argumenty: {' '.join(args)}")
        print("[WRAPPER] Dlya ostanovki nazhmite Ctrl+C")
        print("=" * 80)
        
        # Настройка обработчика сигналов
        signal.signal(signal.SIGINT, self.signal_handler)
        
        try:
            # Запуск основного скрипта
            cmd = [sys.executable, 'main.py'] + args
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=False
            )
            
            self.start_time = time.time()
            self.monitoring = True
            
            # Запуск мониторинга в отдельном потоке
            monitor_thread = threading.Thread(target=self.monitor_output, daemon=True)
            monitor_thread.start()
            
            # Запуск статуса в отдельном потоке
            status_thread = threading.Thread(target=self.print_status, daemon=True)
            status_thread.start()
            
            # Ожидание завершения процесса
            return_code = self.process.wait()
            self.monitoring = False
            
            # Финальная статистика
            elapsed = time.time() - self.start_time
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            
            print("=" * 80)
            print(f"[WRAPPER] Skanirovanie zaversheno")
            print(f"[WRAPPER] Vremya vypolneniya: {minutes:02d}:{seconds:02d}")
            print(f"[WRAPPER] Kod vozvrata: {return_code}")
            print(f"[WRAPPER] Vremya zaversheniya: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            return return_code
            
        except FileNotFoundError:
            print("[WRAPPER] Oshibka: Fayl main.py ne nayden")
            return 1
        except Exception as e:
            print(f"[WRAPPER] Oshibka zapuska: {e}")
            return 1
        finally:
            self.monitoring = False
            if self.process:
                try:
                    if self.process.poll() is None:
                        self.process.terminate()
                        self.process.wait(timeout=5)
                except:
                    pass

def main():
    """Main wrapper function"""
    if len(sys.argv) < 2:
        print("Ispol'zovanie: python wrapper.py [argumenty dlya main.py]")
        print("Primery:")
        print("  python wrapper.py -t example.com")
        print("  python wrapper.py -t 192.168.1.1 -m xss,sqli")
        print("  python wrapper.py -f targets.txt -o report.html")
        sys.exit(1)
    
    # Передаем все аргументы кроме имени скрипта
    scanner_args = sys.argv[1:]
    
    wrapper = ScannerWrapper()
    return_code = wrapper.run_scanner(scanner_args)
    
    sys.exit(return_code)

if __name__ == "__main__":
    main()
