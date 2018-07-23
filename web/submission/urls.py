# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import url
from submission import views
from controllers.submission.routes import SubmissionRoutes
from controllers.submission.api import SubmissionApi
urlpatterns = [
    url(r"^$", views.index, name='submission'),
    url(r"pre/(?P<submit_id>\d+)/$", SubmissionRoutes.presubmit, name="submission/pre"),
    url(r"status/(?P<task_id>\d+)/$", views.status, name='submission_status'),
]
