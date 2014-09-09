import hashlib, hmac
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from traq.projects.models import Project, Component
from traq.tickets.models import Ticket, TicketStatus, TicketPriority

from traq.local_settings import MAILGUN_API_KEY

class DoesNotVerify(Exception):
    def __str__(self):
        return "Request failed to validate"

class InvalidSlug(Exception):
    def __str__(self):
        return "Recipient field failed to validate"

def verify(api_key, token, timestamp, signature):
    # from securing webhooks http://documentation.mailgun.com/user_manual.html#webhooks
    req_hash = hmac.new(
                        key=api_key,
                        msg= timestamp + token,
                        digestmod=hashlib.sha256).hexdigest()
    if signature == req_hash:
        return
    else:
        raise DoesNotVerify()

def ParseEmail(address):
    # this should do some simple validation and return the target project slug
    # TODO: Validate the email address
    # https://github.com/django/django/blob/master/django/core/validators.py#L119
    user_part, domain_part = address.rsplit('@', 1)
    return {'user_part':user_part, 'domain_part':domain_part}

def MapSender(address):
    # Maps the 'sender' address to alternate odin addresses or a non-odin user
    # If part of PDX.edu domain, look up odin account with email address
    # If not part of PDX.edu, create account with trimmed email address as username

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
        except InvalidSlug:
            response.content = "Malformed slug"
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
            # TODO: Create a new user if they don't exist
            created_by = User.objects.create_user(ParseEmail(sender)['user_part'], email=sender)
            created_by.save()

        status = TicketStatus.objects.get(is_default=True)
        priority = TicketPriority.objects.get(is_default=True)
        component = Component.objects.get(is_default=True, project = project)


        t = Ticket(project=project, title=subject, body = body, created_by = created_by, status = status, priority = priority, component = component)
        t.save()
        response.content = "A new ticket has been created"
        return response

# Example: http://documentation.mailgun.com/quickstart-receiving.html#supported-actions-for-routes
# securing webhooks http://documentation.mailgun.com/user_manual.html#webhooks
