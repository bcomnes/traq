import hashlib, hmac, re
from arcutils import ldap
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.contrib.auth.models import User
from traq.projects.models import Project, Component
from traq.tickets.models import Ticket, TicketStatus, TicketPriority, Comment

from traq.local_settings import MAILGUN_API_KEY

def verify(api_key, token, timestamp, signature):
    """Verifies the request against the mailgun MAILGUN_API_KEY"""
    # See http://documentation.mailgun.com/user_manual.html#webhooks
    req_hash = hmac.new(key=api_key,
                        msg=timestamp + token,
                        digestmod=hashlib.sha256).hexdigest()
    if signature == req_hash:
        return True # Its good
    else:
        return False # Nope, Do not trust

def parse_email(address):
    """Returns a dictionary of [user_part]@[donain_part] from the address"""
    EmailValidator(address)
    user_part, domain_part = address.rsplit('@', 1)
    return {'user_part':user_part, 'domain_part':domain_part}

def get_ticket(mail_subject):
    """Returns the ticket object referenced in the subject tag"""
    tags = re.findall(r"\[(.*?)\]", mail_subject)
    if len(tags) > 0:
        # Sample ticket tag: [TRAQ #123]
        tag_number = tags[0].split("#")[1]
        # eg tag_numer should now be '123'
        return Ticket.objects.get(ticket_id=tag_number)
    else:
        return False

def create_ldap_set(address):
    """Returns a set of alternate email addresses from an input email address"""
    qs = "(| (mail={0}) (mailRoutingAddress={0}) (mailLocalAddress={0}))".format(address)
    results = ldap.ldapsearch(qs)

    mail = results[0][1]['mail']
    mail_routing_address = results[0][1]['mailRoutingAddress']
    mail_local_address = results[0][1]['mailLocalAddress']

    return set(mail + mail_routing_address + mail_local_address) - set([address])

def create_new_user(address):
    """Create and return a new User object based on their email address"""

    name = parse_email(address)['user_part'] if parse_email(address)['domain_part'] == 'pdx.edu' else address
    new_user = User.objects.create_user(name, email=address)
    new_user.save()
    return new_user

def create_new_ticket_object(project, subject, body, created_by):
    """Creates and returns a new Ticket Object"""
    status = TicketStatus.objects.get(is_default=True)
    priority = TicketPriority.objects.get(is_default=True)
    component = Component.objects.get(is_default=True, project=project)
    return Ticket(project=project, title=subject, body=body, created_by=created_by, status=status, priority=priority, component=component)

def create_new_comment_object(ticket, body, created_by):
    """Creates and returns a new Comment Object"""
    return Comment(ticket=ticket, body=body, created_by=created_by)

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
            EmailValidator(sender)
        except ValidationError:
            response.content = "Malformed email address"
            response.status_code = 406
            return response

        if not verify(MAILGUN_API_KEY, token, timestamp, signature):
            response.content = "Invalid mailgun token"
            response.status_code = 406
            return response

        try:
            created_by = User.objects.get(email=sender)
        except User.DoesNotExist:
            sender_domain = parse_email(recipient)['domain_part']
            if sender_domain != 'pdx.edu':
                created_by = create_new_user(sender)
            else:
                alt_users = User.objects.filter(email__in=list(create_ldap_set(sender)))
                if len(alt_users) > 0:
                    # TODO: Prioritise alternate email addresses
                    created_by = alt_users[0]
                else:
                    created_by = create_new_user(sender)

        try:
            ticket = get_ticket(subject)
        except Ticket.DoesNotExist:
            response.content = "That ticket does not exist"
            response.status_code = 406
        try:
            project = Project.objects.get(slug=slug)
        except Project.DoesNotExist:
            response.content = "That project does not exist"
            response.status_code = 406

        if ticket:
            # create comment
            new_comment = create_new_comment_object(ticket, body, created_by)
            new_comment.save()
            response.content = "A new comment has been created"
            # notify participating - created_by
        elif project:
            # try to create new ticket
            new_ticket = create_new_ticket(project, subject, body, created_by)
            new_ticket.save()
            response.content = "A new ticket has been created"
            # notify participating
        return response
