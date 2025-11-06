"""
HTML Injection payload collection
"""

class HTMLInjectionPayloads:
    """HTML Injection payload collection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic HTML injection payloads"""
        return [
            "<b>injected</b>",
            "<i>injected</i>",
            "<u>injected</u>",
            "<h1>injected</h1>",
            "<h2>injected</h2>",
            "<p>injected</p>",
            "<div>injected</div>",
            "<span>injected</span>",
            "<strong>injected</strong>",
            "<em>injected</em>",
            "<mark>injected</mark>",
            "<small>injected</small>"
        ]
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced HTML injection payloads"""
        return [
            '<img src="x" alt="injected">',
            '<a href="#" title="injected">link</a>',
            '<input type="text" value="injected">',
            '<textarea>injected</textarea>',
            '<button>injected</button>',
            '<label>injected</label>',
            '<option value="injected">option</option>',
            '<td>injected</td>',
            '<th>injected</th>',
            '<li>injected</li>',
            '<dt>injected</dt>',
            '<dd>injected</dd>'
        ]
    
    @staticmethod
    def get_attribute_payloads():
        """Get HTML attribute injection payloads"""
        return [
            '" title="injected',
            "' title='injected",
            '" alt="injected',
            "' alt='injected",
            '" placeholder="injected',
            "' placeholder='injected",
            '" value="injected',
            "' value='injected",
            '" class="injected',
            "' class='injected",
            '" id="injected',
            "' id='injected"
        ]
    
    @staticmethod
    def get_comment_payloads():
        """Get HTML comment injection payloads"""
        return [
            "<!--injected-->",
            "<!-- injected -->",
            "<!--[if IE]>injected<![endif]-->",
            "<!--[if !IE]>-->injected<!--<![endif]-->",
            "/*injected*/",
            "//injected",
            "#injected"
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all HTML injection payloads"""
        payloads = []
        payloads.extend(HTMLInjectionPayloads.get_basic_payloads())
        payloads.extend(HTMLInjectionPayloads.get_advanced_payloads())
        payloads.extend(HTMLInjectionPayloads.get_attribute_payloads())
        payloads.extend(HTMLInjectionPayloads.get_comment_payloads())
        return payloads
