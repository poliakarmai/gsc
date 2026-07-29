"""
Test: Django IDOR + BAC — cross-tenant, admin panel, sequential enumeration.

Meta-inspired: support ticket access without org/tenant isolation.
"""

from django.db import models
from django.http import JsonResponse


class Ticket(models.Model):
    user = models.ForeignKey("User", on_delete=models.CASCADE)
    number = models.AutoField(primary_key=True)  # AUTOINCREMENT — enables enumeration
    title = models.CharField(max_length=200)


def ticket_detail(request, ticket_id):
    """VULN: Direct PK lookup without ownership OR org/tenant check."""
    ticket = Ticket.objects.get(pk=ticket_id)  # GS007: Django PK + missing org filter
    return JsonResponse({"title": ticket.title})


def admin_ticket_list(request):
    """VULN: Admin view without @staff_member_required."""
    tickets = Ticket.objects.all()
    return JsonResponse({"tickets": list(tickets.values())})


def enumerate_tickets(request):
    """VULN: Sequential ID iteration — ticket enumeration."""
    for ticket_id in range(1, 100):  # GS007: sequential enumeration
        t = Ticket.objects.get(pk=ticket_id)
        print(t.title)


def secure_ticket_detail(request, ticket_id):
    """OK: Has ownership + org check."""
    ticket = Ticket.objects.get(pk=ticket_id, user=request.user, org=request.org)
    return JsonResponse({"title": ticket.title})
