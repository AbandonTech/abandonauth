from pydantic import BaseModel

class DeveloperApplicationDto(BaseModel):
    """Basic data for developer applications"""
    
    id: str
    owner_id: str
