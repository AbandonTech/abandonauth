"""
Entrypoint for local development.

This is the development entry point which can be invoked with the poetry run
script `poetry run dev`. The current working directory is expected to be
fastreactapp/api.
"""

import uvicorn

uvicorn.run("run:app", host="0.0.0.0", port=8000, reload=True)
