from fastapi import APIRouter
from fastapi.responses import RedirectResponse, Response

from ..dependencies.email import SmtpClient

router = APIRouter()


@router.get("/", include_in_schema=False)
async def index() -> Response:
    """Redirect to docs."""
    return RedirectResponse("/docs")


@router.post("/", summary="Begin the registration process")
async def register(email: str) -> None:
    """Create a new AbandonTech account.

    Username is case-insensitive and **unique**.
    """

    email_client = SmtpClient()

    message = (
        "Here is your registration token: 12345\n"
        "You have 15 minutes to create your account using it."
    )

    email_client.send("Registration Token", message, email)
