import threading
try:
    from colorama import init as colorama_init, Fore, Style
except ImportError:
    def colorama_init():
        pass

    class Fore:
        GREEN = CYAN = YELLOW = RED = ""

    class Style:
        RESET_ALL = ""

lock = threading.Lock()

def color_init():
    # initialize colorama (no-op on platforms where not needed)
    try:
        colorama_init()
    except Exception:
        pass

def safe_print(*args, success=False, info=False, warn=False, error=False, **kwargs):
    with lock:
        prefix = ""
        if success:
            prefix = Fore.GREEN + "[+]" + Style.RESET_ALL + " "
        elif info:
            prefix = Fore.CYAN + "[*]" + Style.RESET_ALL + " "
        elif warn:
            prefix = Fore.YELLOW + "[!]" + Style.RESET_ALL + " "
        elif error:
            prefix = Fore.RED + "[-]" + Style.RESET_ALL + " "
        print(prefix, end="")
        print(*args, **kwargs)