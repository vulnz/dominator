#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для запуска бенчмарк-теста на testphp.vulnweb.com
"""

import sys
import os
from core.config import Config
from core.scanner import VulnScanner

def run_benchmark():
    """Запуск бенчмарк-теста"""
    print("=" * 60)
    print("ZAPUSK BENCHMARK-TESTA TESTPHP.VULNWEB.COM")
    print("=" * 60)
    
    # Настройка конфигурации для бенчмарка
    class MockArgs:
        def __init__(self):
            # Основные параметры сканирования
            self.target = 'http://testphp.vulnweb.com/'
            self.targets = ['http://testphp.vulnweb.com/']
            self.file = None
            self.modules = 'xss,sqli,lfi,ssrf,dirbrute,infoleak'
            self.all = False
            
            # Параметры производительности
            self.threads = 5
            self.timeout = 10
            self.request_limit = 1000
            self.limit = 1000  # ДОБАВЛЕН недостающий атрибут
            self.delay = 0
            self.max_time = None
            
            # Параметры отладки и вывода
            self.debug = True
            self.verbose = False
            self.quiet = False
            self.no_color = False
            
            # Параметры HTTP
            self.headers = None
            self.headers_file = None
            self.cookies = None
            self.auth = None
            self.proxy = None
            self.user_agent = None
            self.random_agent = False
            
            # Параметры фильтрации
            self.exclude = None
            self.use_all = False
            
            # Параметры режимов сканирования
            self.filetree_mode = False
            self.filetree = False
            self.single_url = False
            self.nocrawl = False
            self.screenshot = False
            
            # Параметры краулера
            self.crawl_depth = 2
            self.crawl_limit = 100
            
            # Параметры вывода
            self.output = None
            self.format = 'html'
            
            # Дополнительные параметры, которые могут потребоваться
            self.wordlist = None
            self.extensions = None
            self.status_codes = None
            self.follow_redirects = True
            self.verify_ssl = False
            self.session = None
            self.rate_limit = None
            self.retry_count = 3
            self.backoff_factor = 1.0
            self.custom_payloads = None
            self.payload_file = None
            self.scope = None
            self.out_of_scope = None
            self.include_status = None
            self.exclude_status = None
            self.match_regex = None
            self.filter_regex = None
            self.match_size = None
            self.filter_size = None
            self.match_words = None
            self.filter_words = None
            self.match_lines = None
            self.filter_lines = None
            self.recursion_depth = 3
            self.force = False
            self.update = False
            self.config_file = None
            self.save_config = None
            self.load_config = None
            self.resume = None
            self.save_state = None
            self.load_state = None
            
            # Дополнительные атрибуты для полной совместимости с Config
            self.agent = None
            self.referer = None
            self.data = None
            self.method = 'GET'
            self.encoding = 'utf-8'
            self.follow_redirect = True
            self.max_redirect = 5
            self.ignore_cert = True
            self.http_proxy = None
            self.https_proxy = None
            self.socks_proxy = None
            self.bind_host = None
            self.bind_port = None
            self.dns_server = None
            self.dns_timeout = 5
            self.connect_timeout = 10
            self.read_timeout = 30
            self.max_retries = 3
            self.retry_delay = 1
            self.chunk_size = 8192
            self.stream = False
            self.allow_redirects = True
            self.trust_env = True
            self.max_workers = 10
            self.semaphore_limit = 100
            self.queue_size = 1000
            self.batch_size = 50
            self.progress = True
            self.stats = True
            self.benchmark = False
            self.profile = False
            self.memory_limit = None
            self.cpu_limit = None
            self.disk_limit = None
            self.network_limit = None
            self.time_limit = None
            self.request_per_second = None
            self.concurrent_requests = None
            self.max_concurrent = None
            self.throttle = None
            self.backoff = None
            self.jitter = None
            self.circuit_breaker = None
            self.health_check = None
            self.monitoring = None
            self.logging_level = 'INFO'
            self.log_file = None
            self.log_format = None
            self.log_rotation = None
            self.log_retention = None
            self.metrics = None
            self.telemetry = None
            self.tracing = None
            self.sampling = None
            self.export_format = None
            self.export_file = None
            self.import_file = None
            self.template = None
            self.theme = None
            self.style = None
            self.color_scheme = None
            self.font_size = None
            self.font_family = None
            self.page_size = None
            self.margin = None
            self.padding = None
            self.border = None
            self.background = None
            self.foreground = None
            self.highlight = None
            self.shadow = None
            self.animation = None
            self.transition = None
            self.effect = None
            self.filter = None
            self.sort = None
            self.group = None
            self.aggregate = None
            self.transform = None
            self.validate = None
            self.sanitize = None
            self.normalize = None
            self.encode = None
            self.decode = None
            self.compress = None
            self.decompress = None
            self.encrypt = None
            self.decrypt = None
            self.hash = None
            self.sign = None
            self.verify = None
            self.token = None
            self.key = None
            self.secret = None
            self.certificate = None
            self.private_key = None
            self.public_key = None
            self.algorithm = None
            self.mode = None
            self.padding_mode = None
            self.iv = None
            self.salt = None
            self.iterations = None
            self.key_length = None
            self.block_size = None
            self.tag_length = None
            self.aad = None
            self.nonce = None
            self.counter = None
            self.tweak = None
            self.domain = None
            self.subdomain = None
            self.path = None
            self.query = None
            self.fragment = None
            self.scheme = None
            self.host = None
            self.port = None
            self.username = None
            self.password = None
            self.realm = None
            self.nonce_count = None
            self.client_nonce = None
            self.opaque = None
            self.stale = None
            self.qop = None
            self.nc = None
            self.cnonce = None
            self.response_auth = None
            self.nextnonce = None
            self.rspauth = None
            self.digest_uri = None
            self.charset = None
            self.cipher = None
            self.maxbuf = None
            self.servername = None
            self.service = None
            self.hostname = None
            self.authzid = None
            self.authcid = None
            self.passwd = None
            self.mech = None
            self.props = None
            self.security_layer = None
            self.max_ssf = None
            self.min_ssf = None
            self.external_ssf = None
            self.sec_props = None
            self.local_addr = None
            self.remote_addr = None
            self.local_port = None
            self.remote_port = None
            self.peer_addr = None
            self.peer_port = None
            self.sock_family = None
            self.sock_type = None
            self.sock_proto = None
            self.sock_timeout = None
            self.sock_options = None
            self.ssl_context = None
            self.ssl_version = None
            self.ssl_ciphers = None
            self.ssl_cert_reqs = None
            self.ssl_ca_certs = None
            self.ssl_cert_file = None
            self.ssl_key_file = None
            self.ssl_password = None
            self.ssl_crlfile = None
            self.ssl_check_hostname = None
            self.ssl_server_hostname = None
            self.ssl_minimum_version = None
            self.ssl_maximum_version = None
    
    try:
        # Создаем конфигурацию с mock args
        mock_args = MockArgs()
        config = Config(mock_args)
        
        # Устанавливаем дополнительные параметры
        config.headers = {
            'User-Agent': 'Dominator Security Scanner - Benchmark Test'
        }
        
        print(f"Tsel: {config.targets[0]}")
        print(f"Moduli: {', '.join(config.modules)}")
        print(f"Potoki: {config.threads}")
        print(f"Limit zaprosov: {config.request_limit}")
        print("-" * 60)
        
        # Создаем и запускаем сканер
        scanner = VulnScanner(config)
        
        print("Nachinaem skanirovanie...")
        results = scanner.scan()
        
        print("\nSkanirovanie zaversheno!")
        print(f"Najdeno rezultatov: {len(results)}")
        
        # Выводим результаты в консоль
        scanner.print_results(results)
        
        # Сохраняем HTML отчет
        report_filename = "benchmark_report.html"
        scanner.save_report(results, report_filename, 'html')
        
        print(f"\nOtchet sohranen: {report_filename}")
        
        # Проверяем наличие анализа бенчмарка
        benchmark_found = False
        for result in results:
            if 'benchmark_analysis' in result:
                benchmark_found = True
                break
        
        if benchmark_found:
            print("[OK] Analiz benchmarka vypolnen uspeshno!")
            print("[INFO] Proverte HTML otchet dlya detalnogo analiza effektivnosti")
            print("[INFO] Takzhe sozdan tekstovyj otchet benchmark_report_benchmark.txt")
        else:
            print("[WARNING] Analiz benchmarka ne byl vypolnen")
        
        return results
        
    except Exception as e:
        print(f"Oshibka pri vypolnenii benchmarka: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        # Очистка ресурсов
        if 'scanner' in locals():
            scanner.cleanup()

if __name__ == "__main__":
    print("Dominator Security Scanner - Benchmark Test")
    print("Testirovanie effektivnosti na testphp.vulnweb.com")
    print()
    
    results = run_benchmark()
    
    if results:
        print("\n" + "=" * 60)
        print("BENCHMARK-TEST ZAVERSHEN")
        print("=" * 60)
        print("Rezultaty sohraneny v benchmark_report.html")
        print("Otkrojte fajl v brauzere dlya prosmotra detalnogo analiza")
    else:
        print("\n[ERROR] Benchmark-test ne udalsya")
        sys.exit(1)
