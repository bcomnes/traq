import hashlib, hmac
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

def ParseEmail(address):
    validate_email(address)
    user_part, domain_part = address.rsplit('@', 1)
    return {'user_part':user_part, 'domain_part':domain_part}

def LdapAlt(address):
    alt = address # TODO: Actually look up an alternate email address
    return alt

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
            slug = ParseEmail(recipient)['user_part']
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
            try:
                created_by = User.objects.get(email = LdapAlt(sender))
            except User.DoesNotExist:
                created_by = User.objects.created_byuser(sender, email=sender)
                created_by.save()

        status = TicketStatus.objects.get(is_default=True)
        priority = TicketPriority.objects.get(is_default=True)
        component = Component.objects.get(is_default=True, project = project)


        t = Ticket(project=project, title=subject, body = body, created_by = created_by, status = status, priority = priority, component = component)
        t.save()
        response.content = "A new ticket has been created"
        return response
