import sys
from pathlib import Path

# Add parent project directory to sys.path for pytest module discovery
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
