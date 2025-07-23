from django.db import models

class FeatureSample(models.Model):
    ip          = models.GenericIPAddressField(db_index=True)
    path_len    = models.IntegerField()
    kw_hits     = models.IntegerField()
    resp_time   = models.FloatField()
    status_idx  = models.IntegerField()
    burst_count = models.IntegerField()
    total_404   = models.IntegerField()
    label       = models.CharField(max_length=20, default="unlabeled")
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "WAF Feature Sample"
        verbose_name_plural = "WAF Feature Samples"
        indexes = [
            models.Index(fields=["ip"]),
            models.Index(fields=["created_at"]),
        ]

class BlacklistEntry(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason     = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} ({self.reason})"

class DynamicKeyword(models.Model):
    keyword      = models.CharField(max_length=100, unique=True)
    count        = models.PositiveIntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-count']


# Model to store IP addresses that are exempt from blacklisting
class IPExemption(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason     = models.CharField(max_length=100, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} (Exempted: {self.reason})"