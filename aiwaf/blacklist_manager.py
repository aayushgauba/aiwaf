from .models import BlacklistEntry

class BlacklistManager:
    @staticmethod
    def block(ip, reason):
        BlacklistEntry.objects.get_or_create(ip_address=ip, defaults={"reason": reason})

    @staticmethod
    def is_blocked(ip):
        return BlacklistEntry.objects.filter(ip_address=ip).exists()

    @staticmethod
    def all_blocked():
        return BlacklistEntry.objects.all()
