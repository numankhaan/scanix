"""Optional owner-private history; SQLite loads only when history is requested."""
__all__ = ['History']


def __getattr__(name):
    if name == 'History':
        from .store import History
        return History
    raise AttributeError(name)
