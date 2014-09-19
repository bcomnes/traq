import hashlib, hmac
from arcutils import ldap
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.contrib.auth.models import User
from traq.projects.models import Project, Component
from traq.tickets.models import Ticket, TicketStatus, TicketPriority, Comment

from traq.local_settings import MAILGUN_API_KEY

validate_email = EmailValidator()

class DoesNotVerify(Exception):
    """Exception when the request isn't a valid mailgun POST"""
    def __str__(self):
        return "Request failed to validate"

def verify(api_key, token, timestamp, signature):
    """Verifies the request against the mailgun MAILGUN_API_KEY"""
    # See http://documentation.mailgun.com/user_manual.html#webhooks
    req_hash = hmac.new(key=api_key,
                        msg=timestamp + token,
                        digestmod=hashlib.sha256).hexdigest()
    if signature == req_hash:
        return
    else:
        raise DoesNotVerify()

def parse_email(address):
    """Returns a dictionary with the user part and domain part of an email address after making sure the address is a valid email address"""
    validate_email(address)
    user_part, domain_part = address.rsplit('@', 1)
    return {'user_part':user_part, 'domain_part':domain_part}

def create_ldap_set(address):
    """Returns a set of possible alternate email addresses without the input email address"""
    qs = "(| (mail={0}) (mailRoutingAddress={0}) (mailLocalAddress={0}))".format(address)
    results = ldap.ldapsearch(qs)
    
    mail = results[0][1]['mail']
    mailRoutingAddress = results[0][1]['mailRoutingAddress']
    mailLocalAddress = results[0][1]['mailLocalAddress']

    return set(mail + mailRoutingAddress + mailLocalAddress) - set([address])

def create_notify_set(ticket):
    """
    Returns the set of user objects to be notified
    """
    participants = [comment.created_by for comment in ticket.comment_set.all()]
    created = if ticket.created_by [ticket.created_by] else []
    assigned = if ticket.assigned_to [ticket.assigned_to] else []
    spammed = ticket.project.spammed.all()

    return set(participants + created + assigned + spammed)

def create_new_user(address):
    """Create and return a new User object based on their email address"""
    new_user = User.objects.create_user(address, email=address)
    new_user.save()
    return new_user

@csrf_exempt
def index(request):
    #import pdb; pdb.set_trace()
    if request.method == 'GET':
        return HttpResponse("Hi!  You don't look like email")

    elif request.method == 'POST':
        response = HttpResponse()

        try:
            token = request.POST['token']
            timestamp = request.POST['timestamp']
            signature = request.POST['signature']
            recipient = request.POST['recipient']
            sender = request.POST['sender']
            subject = request.POST['subject']
            body = request.POST['stripped-text']
        except KeyError:
            response.content = "Missing critical fields"
            response.status_code = 406
            return response

        try:
            slug = parse_email(recipient)['user_part']
            sender_domain = parse_email(recipient)['domain_part']
            validate_email(sender)
        except ValidationError:
            response.content = "Malformed email address"
            response.status_code = 406
            return response

        try:
            verify(MAILGUN_API_KEY, token, timestamp, signature)
        except DoesNotVerify:
            response.content = "Invalid mailgun token"
            response.status_code = 406
            return response

        try:
            project = Project.objects.get(slug=slug)
        except Project.DoesNotExist:
            response.content = "That project does not exist"
            response.status_code = 406
            return response

        try:
            created_by = User.objects.get(email=sender)
        except User.DoesNotExist:
            if sender_domain != 'pdx.edu':
                created_by = create_new_user(sender)
            else:
                alt_users = User.objects.filter(email__in=list(create_ldap_set(sender)))
                if len(alt_users) > 0:
                    created_by = alt_users[0]
                else:
                    created_by = create_new_user(sender)

        status = TicketStatus.objects.get(is_default=True)
        priority = TicketPriority.objects.get(is_default=True)
        component = Component.objects.get(is_default=True, project=project)
        new_ticket = Ticket(project=project, title=subject, body=body, created_by=created_by, status=status, priority=priority, component=component)
        new_ticket.save()
        response.content = "A new ticket has been created"
        return response

        #if created_by.groups.filter(name__in=['arcstaff', 'arc']).exists():
        #    # Stuff
        #else:
        #    new_todo = ToDo(project=project, title=subject, body = body, #created_by = created_by, status = status, priority = priority, #component = component)
        #    new_todo.save()
        #    response.content = "A new todo has been    created"
