"""Entrypoint for local development.

This is the development entry point which can be invoked with the poetry run
script `poetry run dev`. The current working directory is expected to be
fastreactapp/api.
"""

import uvicorn


def main() -> None:
    """Run server with hot reloading."""
    uvicorn.run(
        "abandonauth.app:app",
        host="127.0.0.1",
        port=8000,
        env_file=".env",
        reload=True)


main()
