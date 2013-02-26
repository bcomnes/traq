from django import forms
from .models import Project, Component
from ..tickets.models import Ticket

class ProjectForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        created_by = kwargs.pop('created_by')
        super(ProjectForm, self).__init__(*args, **kwargs)
        self.instance.created_by = created_by

    class Meta:
        model = Project
        exclude = ("created_by",)

class ComponentForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        project = kwargs.pop('project')
        created_by = kwargs.pop('created_by')
        super(ComponentForm, self).__init__(*args, **kwargs)
        self.instance.project = project
        self.instance.created_by = created_by

        if not self.is_bound:
            try:
                rank = Component.objects.order_by('-rank').all()[0].rank + 1
            except IndexError:
                rank = 1
            self.fields['rank'].initial = rank

    def clean_is_deleted(self):
        # if this is an existing component, don't allow it to be deleted if
        # there are tickets in it
        is_deleted = self.cleaned_data['is_deleted']
        if is_deleted and self.instance.pk:
            count = Ticket.objects.filter(project=self.instance.project, component=self.instance).count()
            if count != 0:
                raise forms.ValidationError("You cannot delete a component with tickets still in it")
        return is_deleted

    class Meta:
        model = Component
        exclude = ('project', 'created_by')
