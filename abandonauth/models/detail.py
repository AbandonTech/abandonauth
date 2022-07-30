from pydantic import BaseModel


class DetailDto(BaseModel):
    """A success response with a detail message."""

    detail: str
