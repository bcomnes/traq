from django.contrib import admin    
from traq.tickets.models import Ticket, TicketType, TicketStatus, WorkType, TicketPriority

admin.site.register(TicketType)
admin.site.register(TicketStatus)
admin.site.register(WorkType)
admin.site.register(TicketPriority)
