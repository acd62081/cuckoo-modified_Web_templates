# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import pymongo

from django.conf import settings
from django.http import HttpResponse, HttpRequest
from django.shortcuts import render
from django.views.decorators.http import require_safe
from django.contrib.auth.decorators import login_required


from wsgiref.util import FileWrapper
from django.http import StreamingHttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING
from utils import render_template
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from api.views import cuckoo_status
from analysis.views import perform_malscore_search
from compare.views import *
from utils import render_template
#from web.controllers.cuckoo.api import  CuckooApi
# Conditional decorator for web authentication
#dataarg = request.POST.get("argument", "")
#malware_family=results_db.analysis.find({"malfamily": {"$regex": dataarg, "$options": "-i"}}).sort([["_id", -1]])
print perform_malscore_search
class conditional_login_required(object):
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition
    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request):
    version = CUCKOO_VERSION

    report = {
       "report_version": version,
    }

    return render_template(request, "dashboard/index.html", report=report)
