from django import template
from django.utils.html import format_html
from django.conf import settings

register = template.Library()

@register.simple_tag
def honeypot_field(field_name=None):
    """
    Legacy honeypot field - no longer needed with timing-based honeypot.
    Returns empty string to maintain backward compatibility.
    """
    return ""
