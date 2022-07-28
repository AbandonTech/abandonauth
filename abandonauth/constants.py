from pathlib import Path

import toml

with open(Path(__file__).parent / ".." / "pyproject.toml", "r") as f:
    metadata = toml.load(f)

# Read from pyproject.toml
version = metadata["tool"]["poetry"]["version"]
