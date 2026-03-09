import sys
from pathlib import Path


if __package__:
    # Module mode: python -m TCPClient.main
    from .core import main
else:
    # Script mode: python TCPClient/main.py or absolute path to this file
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from TCPClient.core import main

if __name__ == "__main__":
    main()
