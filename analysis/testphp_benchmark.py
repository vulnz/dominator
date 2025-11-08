"""
TestPHP Vulnerability Benchmark
Эталонные данные уязвимостей testphp.vulnweb.com для анализа эффективности сканера
"""

from typing import Dict, List, Set, Tuple, Any
from urllib.parse import urlparse, parse_qs
import re

class TestPHPBenchmark:
    """Класс для сравнения результатов сканирования с известными уязвимостями testphp.vulnweb.com"""
    
    def __init__(self):
        self.known_vulnerabilities = self._load_known_vulnerabilities()
        self.known_files = self._load_known_files()
        self.known_directories = self._load_known_directories()
        self.known_info_disclosure = self._load_known_info_disclosure()
    
    def _load_known_vulnerabilities(self) -> Dict[str, List[Dict[str, Any]]]:
        """Загрузка известных уязвимостей из GitHub репозитория"""
        return {
            'xss': [
                {
                    'method': 'POST',
                    'url': 'http://testphp.vulnweb.com/search.php',
                    'parameter': 'searchFor',
                    'type': 'reflected_xss'
                },
                {
                    'method': 'POST', 
                    'url': 'http://testphp.vulnweb.com/guestbook.php',
                    'parameter': 'name',
                    'type': 'reflected_xss'
                },
                {
                    'method': 'POST',
                    'url': 'http://testphp.vulnweb.com/secured/newuser.php',
                    'parameter': 'uuname',
                    'type': 'reflected_xss'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/listproducts.php',
                    'parameter': 'cat',
                    'type': 'reflected_xss'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/listproducts.php',
                    'parameter': 'artist',
                    'type': 'reflected_xss'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/hpp/',
                    'parameter': 'pp',
                    'type': 'reflected_xss'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/hpp/params.php',
                    'parameter': 'p',
                    'type': 'reflected_xss'
                }
            ],
            'sqli': [
                {
                    'method': 'POST',
                    'url': 'http://testphp.vulnweb.com/secured/newuser.php',
                    'parameter': 'uuname',
                    'type': 'error_based'
                },
                {
                    'method': 'POST',
                    'url': 'http://testphp.vulnweb.com/userinfo.php',
                    'parameter': 'uname',
                    'type': 'blind'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/artists.php',
                    'parameter': 'artist',
                    'type': 'error_based'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/listproducts.php',
                    'parameter': 'cat',
                    'type': 'error_based'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/listproducts.php',
                    'parameter': 'artist',
                    'type': 'error_based'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/product.php',
                    'parameter': 'pic',
                    'type': 'error_based'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/Mod_Rewrite_Shop/details.php',
                    'parameter': 'id',
                    'type': 'error_based'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/AJAX/infocateg.php',
                    'parameter': 'id',
                    'type': 'error_based'
                }
            ],
            'lfi': [
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/showimage.php',
                    'parameter': 'file',
                    'type': 'local_file_inclusion',
                    'payload_example': 'showimage.php'
                },
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/showimage.php',
                    'parameter': 'file',
                    'type': 'php_filter',
                    'payload_example': 'php://filter/convert.base64-encode/resource=showimage.php'
                }
            ],
            'ssrf': [
                {
                    'method': 'GET',
                    'url': 'http://testphp.vulnweb.com/showimage.php',
                    'parameter': 'file',
                    'type': 'server_side_request_forgery',
                    'payload_example': 'http://127.0.0.1:22'
                }
            ]
        }
    
    def _load_known_files(self) -> List[str]:
        """Загрузка известных чувствительных файлов"""
        return [
            'http://testphp.vulnweb.com/index.zip',
            'http://testphp.vulnweb.com/.idea/workspace.xml',
            'http://testphp.vulnweb.com/admin/',
            'http://testphp.vulnweb.com/Mod_Rewrite_Shop/.htaccess',
            'http://testphp.vulnweb.com/crossdomain.xml',
            'http://testphp.vulnweb.com/CVS/Root',
            'http://testphp.vulnweb.com/secured/phpinfo.php',
            'http://testphp.vulnweb.com/_mmServerScripts/mysql.php'
        ]
    
    def _load_known_directories(self) -> List[str]:
        """Загрузка известных директорий с листингом"""
        return [
            'http://testphp.vulnweb.com/Flash/',
            'http://testphp.vulnweb.com/CVS/',
            'http://testphp.vulnweb.com/.idea/'
        ]
    
    def _load_known_info_disclosure(self) -> List[str]:
        """Загрузка известных случаев утечки информации"""
        return [
            'wvs@acunetix.com',
            'test@gmail.com', 
            'http://127.0.0.1',
            'wasp@acunetix.com'
        ]
    
    def analyze_scan_results(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Анализ результатов сканирования по сравнению с известными уязвимостями
        
        Args:
            scan_results: Результаты сканирования от VulnScanner
            
        Returns:
            Словарь с анализом эффективности
        """
        analysis = {
            'summary': {
                'total_known_vulnerabilities': self._count_total_known_vulnerabilities(),
                'total_found_vulnerabilities': len([r for r in scan_results if r.get('vulnerability')]),
                'detection_rate': 0.0,
                'false_positive_rate': 0.0
            },
            'by_category': {},
            'missed_vulnerabilities': [],
            'false_positives': [],
            'correctly_identified': [],
            'detailed_analysis': {}
        }
        
        # Анализ по категориям
        for vuln_type in ['xss', 'sqli', 'lfi', 'ssrf']:
            category_analysis = self._analyze_category(vuln_type, scan_results)
            analysis['by_category'][vuln_type] = category_analysis
            
            # Добавляем в общие списки
            analysis['missed_vulnerabilities'].extend(category_analysis['missed'])
            analysis['false_positives'].extend(category_analysis['false_positives'])
            analysis['correctly_identified'].extend(category_analysis['correctly_identified'])
        
        # Анализ файлов и директорий
        file_analysis = self._analyze_files_and_directories(scan_results)
        analysis['by_category']['files_and_directories'] = file_analysis
        analysis['missed_vulnerabilities'].extend(file_analysis['missed'])
        analysis['correctly_identified'].extend(file_analysis['correctly_identified'])
        
        # Анализ утечки информации
        info_analysis = self._analyze_information_disclosure(scan_results)
        analysis['by_category']['information_disclosure'] = info_analysis
        analysis['missed_vulnerabilities'].extend(info_analysis['missed'])
        analysis['correctly_identified'].extend(info_analysis['correctly_identified'])
        
        # Расчет общих метрик
        total_known = analysis['summary']['total_known_vulnerabilities']
        total_found = len(analysis['correctly_identified'])
        total_false_positives = len(analysis['false_positives'])
        total_scanner_findings = analysis['summary']['total_found_vulnerabilities']
        
        if total_known > 0:
            analysis['summary']['detection_rate'] = (total_found / total_known) * 100
        
        if total_scanner_findings > 0:
            analysis['summary']['false_positive_rate'] = (total_false_positives / total_scanner_findings) * 100
        
        # Детальный анализ
        analysis['detailed_analysis'] = self._generate_detailed_analysis(analysis)
        
        return analysis
    
    def _count_total_known_vulnerabilities(self) -> int:
        """Подсчет общего количества известных уязвимостей"""
        total = 0
        for vuln_type, vulns in self.known_vulnerabilities.items():
            total += len(vulns)
        total += len(self.known_files)
        total += len(self.known_directories)
        total += len(self.known_info_disclosure)
        return total
    
    def _analyze_category(self, vuln_type: str, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Анализ конкретной категории уязвимостей"""
        known_vulns = self.known_vulnerabilities.get(vuln_type, [])
        found_vulns = [r for r in scan_results if r.get('module') == vuln_type and r.get('vulnerability')]
        
        correctly_identified = []
        false_positives = []
        missed = []
        
        # Проверяем каждую известную уязвимость
        for known_vuln in known_vulns:
            found_match = False
            
            for found_vuln in found_vulns:
                if self._is_vulnerability_match(known_vuln, found_vuln):
                    correctly_identified.append({
                        'known': known_vuln,
                        'found': found_vuln,
                        'match_confidence': self._calculate_match_confidence(known_vuln, found_vuln)
                    })
                    found_match = True
                    break
            
            if not found_match:
                missed.append(known_vuln)
        
        # Проверяем ложные срабатывания
        for found_vuln in found_vulns:
            is_false_positive = True
            
            for known_vuln in known_vulns:
                if self._is_vulnerability_match(known_vuln, found_vuln):
                    is_false_positive = False
                    break
            
            if is_false_positive:
                false_positives.append(found_vuln)
        
        return {
            'total_known': len(known_vulns),
            'total_found': len(found_vulns),
            'correctly_identified': correctly_identified,
            'false_positives': false_positives,
            'missed': missed,
            'detection_rate': (len(correctly_identified) / len(known_vulns) * 100) if known_vulns else 0,
            'false_positive_rate': (len(false_positives) / len(found_vulns) * 100) if found_vulns else 0
        }
    
    def _is_vulnerability_match(self, known_vuln: Dict[str, Any], found_vuln: Dict[str, Any]) -> bool:
        """Проверка соответствия найденной уязвимости известной"""
        # Нормализация URL
        known_url = self._normalize_url(known_vuln['url'])
        found_url = self._normalize_url(found_vuln.get('target', ''))
        
        # Проверка URL
        if not self._urls_match(known_url, found_url):
            return False
        
        # Проверка параметра
        known_param = known_vuln.get('parameter', '').lower()
        found_param = found_vuln.get('parameter', '').lower()
        
        if known_param and found_param:
            if known_param not in found_param and found_param not in known_param:
                return False
        
        return True
    
    def _normalize_url(self, url: str) -> str:
        """Нормализация URL для сравнения"""
        if not url:
            return ''
        
        try:
            parsed = urlparse(url)
            # Убираем параметры запроса для сравнения базового URL
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return normalized.rstrip('/')
        except:
            return url.rstrip('/')
    
    def _urls_match(self, url1: str, url2: str) -> bool:
        """Проверка соответствия URL"""
        if not url1 or not url2:
            return False
        
        # Точное совпадение
        if url1 == url2:
            return True
        
        # Проверка с учетом различий в схеме (http/https)
        url1_parts = url1.replace('https://', 'http://')
        url2_parts = url2.replace('https://', 'http://')
        
        if url1_parts == url2_parts:
            return True
        
        # Проверка совпадения пути без учета домена
        try:
            path1 = urlparse(url1).path
            path2 = urlparse(url2).path
            return path1 == path2
        except:
            return False
    
    def _calculate_match_confidence(self, known_vuln: Dict[str, Any], found_vuln: Dict[str, Any]) -> float:
        """Расчет уверенности в соответствии уязвимостей"""
        confidence = 0.0
        
        # URL совпадение (40%)
        if self._urls_match(known_vuln['url'], found_vuln.get('target', '')):
            confidence += 0.4
        
        # Параметр совпадение (30%)
        known_param = known_vuln.get('parameter', '').lower()
        found_param = found_vuln.get('parameter', '').lower()
        if known_param and found_param and known_param == found_param:
            confidence += 0.3
        elif known_param and found_param and (known_param in found_param or found_param in known_param):
            confidence += 0.15
        
        # Метод совпадение (20%)
        known_method = known_vuln.get('method', 'GET').upper()
        found_method = 'POST' if 'form' in found_vuln.get('vulnerability', '').lower() else 'GET'
        if known_method == found_method:
            confidence += 0.2
        
        # Тип уязвимости (10%)
        if 'type' in known_vuln:
            vuln_name = found_vuln.get('vulnerability', '').lower()
            if known_vuln['type'] in vuln_name or any(word in vuln_name for word in known_vuln['type'].split('_')):
                confidence += 0.1
        
        return confidence
    
    def _analyze_files_and_directories(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Анализ обнаружения файлов и директорий"""
        dirbrute_results = [r for r in scan_results if r.get('module') == 'dirbrute']
        
        correctly_identified = []
        missed = []
        
        all_known_paths = self.known_files + self.known_directories
        
        for known_path in all_known_paths:
            found_match = False
            
            for result in dirbrute_results:
                if self._is_path_match(known_path, result.get('request_url', '')):
                    correctly_identified.append({
                        'known': known_path,
                        'found': result
                    })
                    found_match = True
                    break
            
            if not found_match:
                missed.append(known_path)
        
        return {
            'total_known': len(all_known_paths),
            'total_found': len(dirbrute_results),
            'correctly_identified': correctly_identified,
            'missed': missed,
            'detection_rate': (len(correctly_identified) / len(all_known_paths) * 100) if all_known_paths else 0
        }
    
    def _is_path_match(self, known_path: str, found_url: str) -> bool:
        """Проверка соответствия путей"""
        if not known_path or not found_url:
            return False
        
        try:
            known_parsed = urlparse(known_path)
            found_parsed = urlparse(found_url)
            
            # Сравниваем пути
            known_path_clean = known_parsed.path.rstrip('/')
            found_path_clean = found_parsed.path.rstrip('/')
            
            return known_path_clean == found_path_clean
        except:
            return False
    
    def _analyze_information_disclosure(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Анализ обнаружения утечек информации"""
        info_results = [r for r in scan_results if r.get('module') == 'infoleak']
        
        correctly_identified = []
        missed = []
        
        for known_info in self.known_info_disclosure:
            found_match = False
            
            for result in info_results:
                evidence = result.get('evidence', '')
                if known_info in evidence:
                    correctly_identified.append({
                        'known': known_info,
                        'found': result
                    })
                    found_match = True
                    break
            
            if not found_match:
                missed.append(known_info)
        
        return {
            'total_known': len(self.known_info_disclosure),
            'total_found': len(info_results),
            'correctly_identified': correctly_identified,
            'missed': missed,
            'detection_rate': (len(correctly_identified) / len(self.known_info_disclosure) * 100) if self.known_info_disclosure else 0
        }
    
    def _generate_detailed_analysis(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Генерация детального анализа"""
        return {
            'strengths': self._identify_strengths(analysis),
            'weaknesses': self._identify_weaknesses(analysis),
            'recommendations': self._generate_recommendations(analysis),
            'coverage_by_owasp': self._analyze_owasp_coverage(analysis),
            'severity_distribution': self._analyze_severity_distribution(analysis)
        }
    
    def _identify_strengths(self, analysis: Dict[str, Any]) -> List[str]:
        """Определение сильных сторон сканера"""
        strengths = []
        
        for category, data in analysis['by_category'].items():
            if data.get('detection_rate', 0) >= 80:
                strengths.append(f"Отличное обнаружение {category.upper()} уязвимостей ({data['detection_rate']:.1f}%)")
            elif data.get('detection_rate', 0) >= 60:
                strengths.append(f"Хорошее обнаружение {category.upper()} уязвимостей ({data['detection_rate']:.1f}%)")
        
        if analysis['summary']['false_positive_rate'] < 10:
            strengths.append(f"Низкий уровень ложных срабатываний ({analysis['summary']['false_positive_rate']:.1f}%)")
        
        return strengths
    
    def _identify_weaknesses(self, analysis: Dict[str, Any]) -> List[str]:
        """Определение слабых сторон сканера"""
        weaknesses = []
        
        for category, data in analysis['by_category'].items():
            if data.get('detection_rate', 0) < 50:
                weaknesses.append(f"Низкое обнаружение {category.upper()} уязвимостей ({data['detection_rate']:.1f}%)")
        
        if analysis['summary']['false_positive_rate'] > 20:
            weaknesses.append(f"Высокий уровень ложных срабатываний ({analysis['summary']['false_positive_rate']:.1f}%)")
        
        return weaknesses
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Генерация рекомендаций по улучшению"""
        recommendations = []
        
        for category, data in analysis['by_category'].items():
            if data.get('detection_rate', 0) < 70:
                recommendations.append(f"Улучшить детекторы для {category.upper()} уязвимостей")
                
                # Специфичные рекомендации
                if category == 'sqli':
                    recommendations.append("Добавить больше SQL error patterns и blind SQL injection техник")
                elif category == 'xss':
                    recommendations.append("Расширить набор XSS payloads и улучшить обнаружение отражения")
                elif category == 'lfi':
                    recommendations.append("Добавить больше LFI payloads включая PHP wrappers")
        
        if analysis['summary']['false_positive_rate'] > 15:
            recommendations.append("Улучшить фильтрацию ложных срабатываний")
        
        return recommendations
    
    def _analyze_owasp_coverage(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Анализ покрытия OWASP Top 10"""
        owasp_mapping = {
            'xss': 'A03:2021 – Injection',
            'sqli': 'A03:2021 – Injection',
            'lfi': 'A03:2021 – Injection',
            'ssrf': 'A10:2021 – Server-Side Request Forgery'
        }
        
        coverage = {}
        for vuln_type, owasp_category in owasp_mapping.items():
            if vuln_type in analysis['by_category']:
                coverage[owasp_category] = analysis['by_category'][vuln_type]['detection_rate']
        
        return coverage
    
    def _analyze_severity_distribution(self, analysis: Dict[str, Any]) -> Dict[str, int]:
        """Анализ распределения по серьезности"""
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        for identified in analysis['correctly_identified']:
            found_vuln = identified.get('found', {})
            severity = found_vuln.get('severity', 'Unknown')
            if severity in severity_count:
                severity_count[severity] += 1
        
        return severity_count
    
    def generate_benchmark_report(self, analysis: Dict[str, Any]) -> str:
        """Генерация текстового отчета о бенчмарке"""
        report = []
        report.append("=" * 80)
        report.append("TESTPHP.VULNWEB.COM BENCHMARK ANALYSIS")
        report.append("=" * 80)
        report.append("")
        
        # Общая статистика
        summary = analysis['summary']
        report.append("ОБЩАЯ СТАТИСТИКА:")
        report.append(f"  Известных уязвимостей: {summary['total_known_vulnerabilities']}")
        report.append(f"  Найдено сканером: {summary['total_found_vulnerabilities']}")
        report.append(f"  Правильно определено: {len(analysis['correctly_identified'])}")
        report.append(f"  Пропущено: {len(analysis['missed_vulnerabilities'])}")
        report.append(f"  Ложных срабатываний: {len(analysis['false_positives'])}")
        report.append(f"  Коэффициент обнаружения: {summary['detection_rate']:.1f}%")
        report.append(f"  Коэффициент ложных срабатываний: {summary['false_positive_rate']:.1f}%")
        report.append("")
        
        # Анализ по категориям
        report.append("АНАЛИЗ ПО КАТЕГОРИЯМ:")
        report.append("-" * 50)
        for category, data in analysis['by_category'].items():
            report.append(f"{category.upper()}:")
            report.append(f"  Известно: {data['total_known']}")
            report.append(f"  Найдено: {data['total_found']}")
            report.append(f"  Правильно: {len(data['correctly_identified'])}")
            report.append(f"  Пропущено: {len(data['missed'])}")
            if 'false_positives' in data:
                report.append(f"  Ложных: {len(data['false_positives'])}")
            report.append(f"  Обнаружение: {data['detection_rate']:.1f}%")
            report.append("")
        
        # Пропущенные уязвимости
        if analysis['missed_vulnerabilities']:
            report.append("ПРОПУЩЕННЫЕ УЯЗВИМОСТИ:")
            report.append("-" * 50)
            for missed in analysis['missed_vulnerabilities'][:10]:  # Показываем первые 10
                if isinstance(missed, dict):
                    report.append(f"  {missed.get('method', 'GET')} {missed.get('url', 'N/A')} [{missed.get('parameter', 'N/A')}]")
                else:
                    report.append(f"  {missed}")
            if len(analysis['missed_vulnerabilities']) > 10:
                report.append(f"  ... и еще {len(analysis['missed_vulnerabilities']) - 10}")
            report.append("")
        
        # Рекомендации
        if analysis['detailed_analysis']['recommendations']:
            report.append("РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ:")
            report.append("-" * 50)
            for rec in analysis['detailed_analysis']['recommendations']:
                report.append(f"  • {rec}")
            report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)
