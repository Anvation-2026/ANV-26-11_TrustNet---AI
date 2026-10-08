import datetime as dt
import re
from typing import Annotated, Literal
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, ValidationError

EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

def _email(v: str) -> str:
    if not EMAIL_RE.fullmatch(v):
        raise ValueError("not a valid email address")
    return v

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Email = Annotated[str, StringConstraints(strip_whitespace=True), AfterValidator(_email)]

class Base(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown (hallucinated) params are rejected

class ReadFile(Base):
    path: Text

class DeleteUser(Base):
    user_id: int = Field(gt=0)
    reason: Text

class ExportData(Base):
    dataset: Text
    format: Literal["csv", "json", "xlsx"]

class SendEmail(Base):
    to: Email
    subject: Text
    body: Text

class ProcessPayment(Base):
    recipient: Text
    amount: float = Field(gt=0)
    currency: str = Field(pattern=r"^[A-Z]{3}$")  # ISO-style code, e.g. INR, USD

class ScheduleEvent(Base):
    title: Text
    date: dt.date  # YYYY-MM-DD, must be a real calendar date
    time: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")  # HH:MM, 24-hour
    attendees: list[Email] = Field(min_length=1)

SCHEMAS = {"read_file": ReadFile, "delete_user": DeleteUser, "export_data": ExportData,
           "send_email": SendEmail, "process_payment": ProcessPayment, "schedule_event": ScheduleEvent}

def validate(tool, params):
    """Return an error string if params are invalid for the tool, else None."""
    model = SCHEMAS.get(tool)
    if model is None:
        return f"unknown tool '{tool}'"
    try:
        model(**params)
    except ValidationError as e:
        return "; ".join(f"{'.'.join(map(str, x['loc'])) or 'params'}: {x['msg']}" for x in e.errors())
