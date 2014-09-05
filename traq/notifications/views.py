import hashlib, hmac
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt


from traq.local_settings import MAILGUN_API_KEY

def verify(api_key, token, timestamp, signature):
    # from securing webhooks http://documentation.mailgun.com/user_manual.html#webhooks
    return signature == hmac.new(
                             key=api_key,
                             msg= timestamp + token,
                             digestmod=hashlib.sha256).hexdigest()

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

        api_key = MAILGUN_API_KEY
        token = request.POST['token']
        timestamp = request.POST['timestamp']
        signature = request.POST['signature']

        validate_request = verify(api_key, token, timestamp, signature)

        if validate_request:

            recipient = request.POST['recipient']
            subject = request.POST['subject']
            body = request.POST['']
            slug = get_slug(recipient);
            project = Projects.objects.get(slug = slug)
            t = Ticket(project = project, name = subject, )
            print recipient
            return HttpResponse("POST Request received :)")

        else:
            response = HttpResponse("Your request didnt validate")
            response.status_code = 406
            return response

# Example: http://documentation.mailgun.com/quickstart-receiving.html#supported-actions-for-routes
# securing webhooks http://documentation.mailgun.com/user_manual.html#webhooks
