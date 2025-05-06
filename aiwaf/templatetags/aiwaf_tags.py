from django import template
from django.utils.html import format_html
from django.conf import settings

register = template.Library()

@register.simple_tag
def honeypot_field(field_name=None):

    name = field_name or getattr(settings, "AIWAF_HONEYPOT_FIELD", "hp_field")
    return format_html(
        '<input type="text" name="{}" hidden autocomplete="off" tabindex="-1" />',
        name
    )
