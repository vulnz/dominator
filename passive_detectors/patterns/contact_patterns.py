"""
Contact information patterns for resource collection
"""

def get_contact_patterns():
    """Get patterns for contact information"""
    return {
        'email_addresses': [
            {
                'name': 'Standard Email',
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': 'Low',
                'description': 'Email address detected'
            },
            {
                'name': 'Admin Email',
                'pattern': r'\b(?:admin|administrator|root|support|contact|info|sales|help|webmaster)@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': 'Medium',
                'description': 'Administrative email address detected'
            },
            {
                'name': 'No-Reply Email',
                'pattern': r'\b(?:noreply|no-reply|donotreply)@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': 'Info',
                'description': 'No-reply email address detected'
            }
        ],
        'phone_numbers': [
            {
                'name': 'US Phone Number',
                'pattern': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
                'severity': 'Medium',
                'description': 'US phone number detected'
            },
            {
                'name': 'International Phone',
                'pattern': r'\+[1-9]\d{1,14}\b',
                'severity': 'Medium',
                'description': 'International phone number detected'
            },
            {
                'name': 'Toll-Free Number',
                'pattern': r'\b1?[-.\s]?(?:800|888|877|866|855|844|833|822)[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                'severity': 'Low',
                'description': 'Toll-free phone number detected'
            }
        ],
        'addresses': [
            {
                'name': 'Street Address',
                'pattern': r'\b\d+\s+[A-Za-z0-9\s,.-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl)\b',
                'severity': 'Medium',
                'description': 'Street address detected'
            },
            {
                'name': 'ZIP Code',
                'pattern': r'\b\d{5}(?:-\d{4})?\b',
                'severity': 'Low',
                'description': 'ZIP code detected'
            }
        ]
    }
