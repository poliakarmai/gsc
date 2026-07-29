"""
Test: batch operations + HTTP method override (Gen+Eval approved patterns).

Batch Operations — bulk_create/insertMany without ownership check.
HTTP Method Override — _method parameter / X-HTTP-Method header bypass.
"""

from django.db import models


class Ticket(models.Model):
    user = models.ForeignKey("User", on_delete=models.CASCADE)
    org = models.ForeignKey("Org", on_delete=models.CASCADE)


# ── VULN: Batch operations ──


def bulk_update_tickets(request):
    """VULN: bulk_update without checking all tickets belong to request.user.org."""
    ticket_data = request.POST.getlist("tickets")
    Ticket.objects.bulk_update(  # GS007: batch operation
        [Ticket(id=t["id"], status=t["status"]) for t in ticket_data],
        ["status"],
    )


def bulk_create_orders(request):
    """VULN: bulk_create without checking org ownership."""
    orders = request.POST.getlist("orders")
    Order.objects.bulk_create(  # GS007: batch operation
        [Order(org_id=o["org_id"], amount=o["amount"]) for o in orders]
    )


# ── VULN: HTTP Method Override ──


HTTP_METHOD_OVERRIDE = "X-HTTP-Method-Override"  # GS007: method override header


def parse_method(request):
    """VULN: _method override bypass."""
    _method = request.POST.get("_method", request.method)  # GS007: _method=
    if _method == "DELETE":
        user_id = request.POST["user_id"]
        User.objects.filter(id=user_id).delete()


# ── OK: secure variants ──


def secure_bulk_update(request):
    """OK: checks ownership before bulk_update."""
    ticket_data = [t for t in request.POST.getlist("tickets") if t["org_id"] == request.user.org_id]
    Ticket.objects.bulk_update(  # gsc:ignore
        [Ticket(id=t["id"], status=t["status"]) for t in ticket_data],
        ["status"],
    )
