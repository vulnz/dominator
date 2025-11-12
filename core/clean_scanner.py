"""
Clean modular scanner - Just a module launcher!
NO hardcoded vulnerability logic - modules handle everything
"""

from typing import List, Dict, Any
import time
from core.http_client import HTTPClient
from core.result_manager import ResultManager
from core.report_generator import ReportGenerator
from core.module_loader import ModuleLoader
from core.crawler import WebCrawler
from core.url_parser import URLParser
from core.logger import get_logger

logger = get_logger(__name__)


class ModularScanner:
    """
    Clean modular scanner that just launches modules

    NO hardcoded vulnerability detection!
    Modules handle everything via TXT files
    """

    def __init__(self, config):
        """
        Initialize scanner

        Args:
            config: Scanner configuration
        """
        self.config = config
        self.stop_requested = False

        logger.info("Initializing modular scanner...")

        # Initialize core components
        self.http_client = HTTPClient(
            timeout=config.timeout,
            headers=config.headers,
            cookies=config.cookies,
            rate_limit=config.request_limit
        )

        self.result_manager = ResultManager()
        self.crawler = WebCrawler(config)
        self.url_parser = URLParser()
        self.report_generator = ReportGenerator()

        # Load modules dynamically
        self.module_loader = ModuleLoader()
        self.modules = []

        logger.info(f"Scanner initialized")

    def scan(self) -> List[Dict[str, Any]]:
        """
        Run vulnerability scan

        Returns:
            List of scan results
        """
        logger.info("="*80)
        logger.info("Starting modular vulnerability scan")
        logger.info("="*80)

        start_time = time.time()

        # Get targets
        targets = self.config.get_targets()
        if not targets:
            logger.error("No targets specified")
            return []

        logger.info(f"Scanning {len(targets)} target(s)")

        # Load modules
        self._load_modules()

        if not self.modules:
            logger.error("No modules loaded! Check your -m parameter")
            return []

        all_results = []

        # Scan each target
        for target in targets:
            if self.stop_requested:
                logger.warning("Scan stopped by user request")
                break

            logger.info(f"\nTarget: {target}")
            logger.info("-" * 80)

            # Discover URLs
            discovered_urls = self._discover_pages(target)
            logger.info(f"Discovered {len(discovered_urls)} URLs")

            # Run each module
            for module in self.modules:
                if self.stop_requested:
                    break

                logger.info(f"\nRunning module: {module.get_name()}")
                logger.info(f"Description: {module.get_description()}")

                try:
                    # Module does everything itself!
                    # - Loads payloads from TXT
                    # - Loads patterns from TXT
                    # - Performs scanning
                    # - Returns results
                    module_results = module.scan(discovered_urls, self.http_client)

                    # Add results
                    all_results.extend(module_results)
                    self.result_manager.add_results(module_results)

                    vulnerabilities = len([r for r in module_results if r.get('vulnerability')])
                    logger.info(f"Module '{module.get_name()}' completed: {len(module_results)} findings ({vulnerabilities} vulnerabilities)")

                except Exception as e:
                    logger.error(f"Error in module '{module.get_name()}': {e}")
                    import traceback
                    traceback.print_exc()

        duration = time.time() - start_time
        logger.info(f"\n{'='*80}")
        logger.info(f"Scan completed in {duration:.2f} seconds")
        logger.info(f"{'='*80}\n")

        # Print statistics
        self.result_manager.print_summary()

        return all_results

    def _load_modules(self):
        """Load modules based on configuration"""
        logger.info(f"\nLoading modules: {self.config.modules}")

        self.modules = self.module_loader.load_modules(self.config.modules)

        if not self.modules:
            logger.error("No modules loaded!")
            logger.info("\nAvailable modules:")
            self.module_loader.print_available_modules()
        else:
            logger.info(f"Successfully loaded {len(self.modules)} module(s):")
            for module in self.modules:
                logger.info(f"  - {module.get_name()}: {module.get_description()}")

    def _discover_pages(self, target: str) -> List[Dict[str, Any]]:
        """
        Discover pages and endpoints

        Args:
            target: Target URL

        Returns:
            List of discovered URLs with parameters
        """
        discovered = []

        # Single URL mode - just parse the target
        if self.config.single_url:
            parsed = self.url_parser.parse(target)
            if parsed:
                discovered.append(parsed)
            return discovered

        # Crawl mode
        try:
            logger.info("Starting page discovery...")
            pages = self.crawler.crawl_for_pages(target)

            # IMPORTANT: Add passive scanner findings to result_manager
            # Passive scanner runs during crawling and stores findings in crawler
            passive_findings = self.crawler.get_passive_findings()
            if passive_findings:
                # Add all passive findings to result manager
                for category, findings_list in passive_findings.items():
                    for finding in findings_list:
                        # CRITICAL: Passive findings must have 'vulnerability': True
                        # otherwise result_manager will filter them out!
                        if 'vulnerability' not in finding:
                            finding['vulnerability'] = True

                        # Convert passive finding to result format
                        self.result_manager.add_result(finding)
                logger.info(f"Added {sum(len(v) for v in passive_findings.values())} passive findings to results")

            for page in pages:
                parsed = self.url_parser.parse(page)
                if parsed:
                    discovered.append(parsed)

            # Process found forms and add them as targets
            for form in self.crawler.found_forms:
                form_url = form.get('url', target)
                action = form.get('action', '')

                # Resolve form action URL
                if action:
                    if action.startswith('http'):
                        form_target_url = action
                    else:
                        from urllib.parse import urljoin
                        form_target_url = urljoin(form_url, action)
                else:
                    form_target_url = form_url

                # Create target dict for form
                form_params = {}
                for input_data in form['inputs']:
                    param_name = input_data.get('name', '')
                    if param_name:
                        form_params[param_name] = input_data.get('value', 'test')

                if form_params:
                    form_target = {
                        'url': form_target_url,
                        'params': form_params,
                        'method': form.get('method', 'GET'),
                        'source': 'form'
                    }
                    discovered.append(form_target)
                    logger.info(f"Added form target: {form.get('method')} {form_target_url} with params: {list(form_params.keys())[:5]}")

            logger.info(f"Page discovery complete: {len(discovered)} targets total ({len(self.crawler.found_forms)} from forms)")

        except Exception as e:
            logger.error(f"Error during page discovery: {e}")

        return discovered

    def print_results(self, results: List[Dict[str, Any]]):
        """
        Print scan results

        Args:
            results: List of scan results (ignored, using result_manager instead)
        """
        self.result_manager.print_summary()

        # Use ALL results from result_manager (including passive scanner)
        all_results = self.result_manager.get_all_results()
        vulnerabilities = [r for r in all_results if r.get('vulnerability')]

        if not vulnerabilities:
            print("\n✓ No vulnerabilities found")
            return

        print("\n⚠ VULNERABILITIES FOUND:\n")

        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            severity_results = [r for r in vulnerabilities if r.get('severity') == severity]

            if severity_results:
                print(f"\n{severity} Severity ({len(severity_results)}):")
                print("-" * 80)

                for result in severity_results:
                    print(f"\n  [{result.get('type', 'Unknown')}]")
                    print(f"  URL: {result.get('url', 'N/A')}")
                    if result.get('parameter'):
                        print(f"  Parameter: {result.get('parameter')}")
                    if result.get('payload'):
                        payload_str = str(result.get('payload'))
                        if len(payload_str) > 100:
                            payload_str = payload_str[:100] + "..."
                        print(f"  Payload: {payload_str}")
                    if result.get('evidence'):
                        print(f"  Evidence: {result.get('evidence')[:200]}...")

    def save_report(self, results: List[Dict[str, Any]], output_file: str, format: str = 'html'):
        """
        Save scan report

        Args:
            results: Scan results (ignored, using result_manager instead)
            output_file: Output file path
            format: Report format (html, json, xml, txt)
        """
        # IMPORTANT: Use ALL results from result_manager (including passive scanner)
        # NOT just the 'results' parameter which only contains active module results
        all_results = self.result_manager.get_all_results()

        scan_info = {
            'targets': self.config.get_targets(),
            'modules': [m.get_name() for m in self.modules],
            'total_requests': self.http_client.request_count,
        }

        success = self.report_generator.generate(all_results, output_file, format, scan_info)

        if success:
            logger.info(f"Report saved: {output_file}")
        else:
            logger.error(f"Failed to save report: {output_file}")

    def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up scanner resources")
        self.http_client.close()

    def request_stop(self):
        """Request scan to stop gracefully"""
        logger.warning("Stop requested - scan will terminate")
        self.stop_requested = True
