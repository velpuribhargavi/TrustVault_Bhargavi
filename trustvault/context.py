class _Office:
    available = False

class _Audit:
    def append(self, *args, **kwargs):
        pass

class AppContext:
    def __init__(self, settings=None):
        self.audit = _Audit()
        self.office = _Office()
        self.settings = settings

    @classmethod
    def build(cls, settings, create_keys=False):
        return cls(settings=settings)
