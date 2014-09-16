import hashlib, hmac
from arcutils import ldap
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.contrib.auth.models import User
from traq.projects.models import Project, Component
from traq.tickets.models import Ticket, TicketStatus, TicketPriority

from traq.local_settings import MAILGUN_API_KEY

validate_email = EmailValidator()

class DoesNotVerify(Exception):
    def __str__(self):
        return "Request failed to validate"

def verify(api_key, token, timestamp, signature):
    # See http://documentation.mailgun.com/user_manual.html#webhooks
    req_hash = hmac.new(
                        key=api_key,
                        msg= timestamp + token,
                        digestmod=hashlib.sha256).hexdigest()
    if signature == req_hash:
        return
    else:
        raise DoesNotVerify()

def parse_email(address):
    validate_email(address)
    user_part, domain_part = address.rsplit('@', 1)
    return {'user_part':user_part, 'domain_part':domain_part}

def create_ldap_set(address):
    qs = "(| (mail={0}) (mailRoutingAddress={0}) (mailLocalAddress={0}))".format(address)
    results = ldap.ldapsearch(qs)
    
    mail = results[0][1]['mail']
    mailRoutingAddress = results[0][1]['mailRoutingAddress']
    mailLocalAddress = results[0][1]['mailLocalAddress']

    return set(mail + mailRoutingAddress + mailLocalAddress) - set([address])

def create_new_user(address):
    new_user = User.objects.created_byuser(sender, email=sender)
    new_user.save()
    return new_user

@csrf_exempt
def index(request):
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
            body = request.POST['body-plain']
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
            project = Project.objects.get(slug = slug)
        except Project.DoesNotExist:
            response.content = "That project does not exist"
            response.status_code = 406
            return response

        try:
            created_by = User.objects.get(email = sender)
        except User.DoesNotExist:
            if sender_domain != 'pdx.edu':
                created_by = create_new_user(sender)
            else:
                alt_users = User.objects.filter(email__in= list(create_ldap_set(sender)))
                if len(alt_users) > 0:
                    created_by = alt_users[0]
                else:
                    created_by = create_new_user(sender)

        if created_by.groups.filter(name__in = ['arcstaff','arc']).exists():
            status = TicketStatus.objects.get(is_default=True)
            priority = TicketPriority.objects.get(is_default=True)
            component = Component.objects.get(is_default=True, project = project)
            
            t = Ticket(project=project, title=subject, body = body, created_by = created_by, status = status, priority = priority, component = component)
            t.save()
            response.content = "A new ticket has been created"
        else:
            # Create todo
        return response
