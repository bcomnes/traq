import hashlib, hmac
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt


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
    if signature == hmac.new
        return
    else
        raise DoesNotVerify()

def get_slug(address):
    # this should do some simple validation and return the target project slug
    # TODO: Validate this stuff
    # https://github.com/django/django/blob/master/django/core/validators.py#L119
    user_part, domain_part = address.rsplit('@', 1)
    return user_part

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
            subject = request.POST['subject']
            body = request.POST['body?']
            api_key = MAILGUN_API_KEY
            slug = get_slug(recipient)

            verify(api_key, token, timestamp, signature)
            project = Projects.objects.get(slug = slug)
            t = Ticket(project = project, name = subject, body = body)
            t.save()
            response.content = "A new ticket has been created"
        except DoesNotExist:
            response.content = "That project does not exist"
            response.status_code = 406
        except DoesNotVerify:
            response.content = "Invalid mailgun token"
            response.status_code = 406
        except InvalidSlug:
            response.content = "Malformed email address"
            response.status_code = 406
        finally
            return response

# Example: http://documentation.mailgun.com/quickstart-receiving.html#supported-actions-for-routes
# securing webhooks http://documentation.mailgun.com/user_manual.html#webhooks
