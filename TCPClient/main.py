try:
    # Module mode: python -m TCPClient.main
    from .core import main
except ImportError:
    # Script mode: python TCPClient/main.py
    from TCPClient.core import main

if __name__ == "__main__":
    main()
