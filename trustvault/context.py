class AppContext:
    """Application context holder"""
    def __init__(self):
        self.settings = None
    
    def init(self):
        return self

# Global context instance
app_context = AppContext()
