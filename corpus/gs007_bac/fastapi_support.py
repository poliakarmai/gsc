"""
Test: FastAPI — support panel without auth, file download, cross-org access.

Meta-inspired: support backend with broken access control.
"""

from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from starlette.responses import FileResponse


app = FastAPI()


def get_db():
    ...


def get_current_user():
    ...


def get_current_org():
    ...


# VULN: Support route without auth
@app.get("/support/tickets/{ticket_id}")  # GS007: admin/support route
def get_support_ticket(ticket_id: int, db: Session = Depends(get_db)):
    """No auth check — anyone can access support tickets."""
    return db.query(Ticket).filter(Ticket.id == ticket_id).first()


# VULN: File download without ownership
@app.get("/attachments/{file_id}")  # GS007: file endpoint
def download_attachment(file_id: int):
    """Unprotected file download — no ownership check."""
    return FileResponse(f"/uploads/{file_id}")


# VULN: User auth but missing org auth — cross-org access possible
@app.get("/org/tickets/{ticket_id}")
def get_org_ticket(ticket_id: int, user=Depends(get_current_user)):
    """Has user auth BUT missing org/tenant check."""
    return db.query(Ticket).filter(Ticket.id == ticket_id).first()


# OK: Has both user AND org auth
@app.get("/secure/tickets/{ticket_id}")
def secure_ticket(
    ticket_id: int,
    user=Depends(get_current_user),
    org=Depends(get_current_org),
):
    return db.query(Ticket).filter(
        Ticket.id == ticket_id, Ticket.org_id == org.id
    ).first()
