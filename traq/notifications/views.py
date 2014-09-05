from django.http import HttpResponse
import pprint
pp = pprint.PrettyPrinter(indent=4)

def index(request):
    if request.method == 'GET':
        pp.pprint(request)
        return HttpResponse("Hi!  You don't look like email to me")
    elif request.method == 'POST':
        pp.pprint(request)
        return HttpResponse("POST Request received :)")
