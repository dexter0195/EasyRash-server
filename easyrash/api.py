#Copyright (C) 2016 Carlo De Pieri, Alessio Koci, Gianmaria Pedrini,
#Alessio Trivisonno
#
#This file is part of EasyRash.
#
#EasyRash is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#EasyRash is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

from flask import Flask, request, abort, jsonify, Response , g
from flask_restful import Resource
import json
from easyrash import apiobj,auth,app
from easyrash.models import *
import base64
import datetime
from flask_mail import Message, Mail
from functools import wraps

# DECORATORS

def allowed_roles(*roles):
    '''specify a list of roles allowed to perform an action. Accepts a list of strings chosen between chair, reviewer, author, himself.
    ON FAILURE: deny the access to the user'''
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user = g.user
            allowed = False
            # gets role in the form of (role, resource)
            user_roles = user.get_roles()
            # find out for which resource we are requesting permission
            resource = kwargs.get('paper_id') or kwargs.get('event_id') or kwargs.get('user_id')
            if resource == None:
                abort(400)
            if kwargs.get('paper_id') and 'chair' in roles:
                #user might be a chair trying edit a paper in an event he hosts, in that case
                #we need to get the event because you are chair of the paper event, not the paper
                paper = Paper.objects.get_or_404(url=resource)
                event = paper.event
            elif kwargs.get('event_id'):
                event = resource
            # create allowed_roles with the resource requested, handle chair case separately
            allowed_roles = [(role, resource) if role != 'chair' else ('chair', event) for role in roles]
            relevant_roles = []
            for role in allowed_roles:
                if role in user_roles:
                    allowed = True
                    relevant_roles.append(role)
            if allowed:
                g.roles = relevant_roles
                return f(*args, **kwargs)
            else:
                # if the user had none of the allowed roles
                abort(401)
        return wrapped
    return wrapper

def check_confirmed(func):
    '''check whether a user has finalized his registration by clicking on the confirmation URL sent by email
    ON FAILURE: returns an error of unconfirmed email address''' 
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user = g.user
        if user.confirmed is False:
            resp = Response(response="<h1>User unconfirmed. Please confirm your account first</h1>", status=401, mimetype="text/html")
            return resp
        return func(*args, **kwargs)

    return decorated_function

def check_lock(func):
    '''check if there is another user who is editing the file
    ON FAILURE: returns an error message to the client saying that someone else own the lock'''
        
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user = g.user
        paper_id = kwargs.get('paper_id')
        paper = Paper.objects.get_or_404(url=paper_id)
        now = datetime.datetime.now()
        if (paper.lock > now and user.mail == paper.lockowner): 
            return func(*args, **kwargs)
        resp = Response(response="<h1>Lock already taken</h1>", status=400, mimetype="text/html")
        return resp

    return decorated_function
# HEADERS

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'content-type, authorization, x-requested-with, accept, origin')
    response.headers.add('Access-Control-Allow-Methods', 'PUT, POST, DELETE')
    return response

# RESOURCES

class PaperListAPI(Resource):
    '''list the papers'''
    @auth.login_required
    @check_confirmed
    # no roles required
    def get(self):
        '''returns a json list of paper'''
        # List of Paper, got from db
        summary_fields = ['url', 'event', 'reviewers']
        paperlist = Paper.objects.all().only(*summary_fields).to_json()
        resp = Response(response=paperlist, status=200, mimetype="application/json")
        return(resp)

class PaperLockAPI(Resource):
    '''resource used to interact with papers lock'''

    @auth.login_required
    @check_confirmed
    @allowed_roles('reviewer', 'chair')
    def get(self, paper_id):
        '''Returns the lock and its owner'''
        paper = Paper.objects.get_or_404(url=paper_id)
        resp = Response(response=str(paper.lock), status=200, mimetype="text/html")
        return(resp)

    @auth.login_required
    @check_confirmed
    @allowed_roles('reviewer', 'chair')
    def post(self, paper_id):
        '''update the lock owner and/or the exipiring date'''
        try:
            data = request.get_json();
            paper = Paper.objects.get_or_404(url=paper_id)
            action = data.get('lock_action')
            if action == 'get':
                paper.get_lock(g.user)
                resp = Response(response='lock taken for ' + paper_id, status=200)
            elif action == 'release':
                paper.release_lock(g.user)
                resp = Response(response='lock released for ' + paper_id, status=200)
            else:
                raise Exception('unknown lock_action, must be "get" or "release"')
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

class PaperConversionAPI(Resource):
    '''handle papers download and conversion'''
    @auth.login_required
    @check_confirmed
    # no roles required
    def get(self, paper_id, fformat):
        '''returns paper_id in the file format specified by fformat (if possible) '''
        paper = Paper.objects.get_or_404(url=paper_id)
        if (fformat=='html'):
            resp = Response(response=base64.b64decode(paper.text), status=200, mimetype="text/html")
        else:
            resp = Response(response='file format not supported', status=400)
        return(resp)

class PaperAPI(Resource):
    '''handle paper's actions'''

    @auth.login_required
    @check_confirmed
    # no roles required
    def get(self, paper_id):
        '''returns the requested paper, if it exists'''
        try:
            public_fields = ['title', 'authors', 'event', 'url', 'reviewers', 'text', 'state']
            paper = Paper.objects.get_or_404(url=paper_id)
            paper_dict = json.loads(paper.to_json())
            paper_dict['state'] = paper.get_state()
            filtered_dict = {field : paper_dict[field] for field in public_fields}
            resp = Response(response=json.dumps(filtered_dict), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

    @auth.login_required
    @check_confirmed
    # no roles required
    def put(self, paper_id):
        '''submit a new papaer'''
        allowed_fields = ['title', 'authors', 'event', 'text']
        try:
            paperdata = request.get_json();
            check_fields(paperdata, allowed_fields)
            paperdata['original_text'] = paperdata.get('text')
            paperdata['url'] = paper_id
            if 'authors' not in paperdata:
                paperdata['authors'] = [g.user.mail]
            elif g.user.mail not in paperdata['authors']:
                paperdata['authors'].append(g.user.mail)
            check_duplicates(paperdata, 'authors')
            newpaper = Paper(**paperdata)
            newpaper.save(force_insert=True)
            resp = Response(response=newpaper.to_json(), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

    @auth.login_required
    @check_confirmed
    @allowed_roles('author')
    def delete(self, paper_id):
        '''remove a paper from the list'''
        try:
            paper = Paper.objects.get_or_404(url=paper_id)
            paper.delete()
            resp = Response(response=paper_id + ' deleted', status=200)
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

    @auth.login_required
    @check_confirmed
    @allowed_roles('reviewer', 'chair')
    @check_lock
    def post(self, paper_id):
        '''edit a paper'''
        allowed_reviewer_fields = ['text']
        allowed_chair_fields = ['text', 'reviewers']
        try:
            paperdata = request.get_json();
            paper = Paper.objects.get_or_404(url=paper_id)
            old_reviewers = paper.reviewers
            new_reviewers = paperdata.get('reviewers')
            #maps roles to the fields they are allowed to edit
            allowed_role_fields = {('chair', paper.event) : allowed_chair_fields, ('reviewer', paper_id) : allowed_reviewer_fields}
            allowed_fields = []
            for role in allowed_role_fields:
                if role in g.roles:
                    allowed_fields += allowed_role_fields[role]
            check_fields(paperdata, allowed_fields)
            check_duplicates(paperdata, 'reviewers')
            paper.update(**paperdata)
            paper.save()
            if new_reviewers:
                for reviewer in new_reviewers:
                    if reviewer not in old_reviewers:
                        send_role_assignment_email(reviewer, 'reviewer', paper.title)
            resp = Response(response=paper.to_json(), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

class FinalizeEventAPI(Resource):
    '''sends all the accepted papers to the publisher'''

    @auth.login_required
    @check_confirmed
    # no roles required
    def post(self, event_id):
        try:
            data = request.get_json();
            publisher_email = data['publisher_email']
            event = Event.objects.get_or_404(acronym=event_id)
            submissions = event.get_submissions()
            attachments = {}
            for paper in submissions:
                paper = Paper.objects.get_or_404(url=paper)
                state = paper.get_state()
                if state != 'pso:accepted-for-publication' and state != 'pso:rejected-for-publication':
                    raise Exception("Can't finalize. Not all paper are decided yet.")
                if state == 'pso:accepted-for-publication':
                    attachments[paper.url] = base64.b64decode(paper.text)
            send_publishing_email(publisher_email, event.acronym, attachments)
            resp = Response(response="Event finalized successfully!", status=200)
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

class EventListAPI(Resource):
    '''returns the list of events'''

    @auth.login_required
    @check_confirmed
    # no roles required
    def get(self):
        '''returns a json list of events'''
        # List of Events, got from db
        summary_fields = ['acronym', 'conference', 'description', 'date']
        eventlist = Event.objects.all().only(*summary_fields).to_json()
        eventlist_pylist = json.loads(eventlist)
        for event in eventlist_pylist:
            event['date'] = event['date']['$date']
        resp = Response(response=json.dumps(eventlist_pylist), status=200, mimetype="application/json")
        return(resp)

class EventAPI(Resource):
    '''handle the events'''

    @auth.login_required
    @check_confirmed
    # no roles required
    def get(self, event_id):
        '''returns the requested event, if it exists'''
        public_fields = ['conference', 'acronym', 'chairs', 'description', 'date', 'state', 'pc_members', 'submissions']
        try:
            event = Event.objects.get_or_404(acronym=event_id)
            event_dict = json.loads(event.to_json())
            event_dict['pc_members'] = event.get_pc_members()
            event_dict['submissions'] = event.get_submissions()
            event_dict['date'] = event_dict['date']['$date']
            filtered_dict = {field : event_dict[field] for field in public_fields}
            resp = Response(response=json.dumps(filtered_dict), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp
    

    @auth.login_required
    @check_confirmed
    # no roles required
    def put(self, event_id):
        '''create a new event'''
        allowed_fields = ['conference', 'chairs', 'description', 'date']
        try:
            eventdata = request.get_json();
            check_fields(eventdata, allowed_fields)
            eventdata['acronym'] = event_id
            if g.user.mail not in eventdata['chairs']:
                eventdata['chairs'].append(g.user.mail)
            check_duplicates(eventdata, 'chairs')
            newevent = Event(**eventdata)
            newevent.save(force_insert=True)
            for chair in eventdata['chairs']:
                send_role_assignment_email(chair, 'chair', eventdata['conference'])
            resp = Response(response=newevent.to_json(), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

    @auth.login_required
    @check_confirmed
    @allowed_roles('chair')
    def delete(self, event_id):
        '''delete an event'''
        try:
            event = Event.objects.get_or_404(acronym=event_id)
            event.delete()
            resp = Response(response=event_id + ' deleted', status=200)
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

    @auth.login_required
    @check_confirmed
    @allowed_roles('chair')
    def post(self, event_id):
        allowed_fields = ['conference', 'chairs', 'description', 'date', 'state']
        '''edit an event'''
        try:
            eventdata = request.get_json();
            event = Event.objects.get_or_404(acronym=event_id)
            old_chairs = event.chairs
            new_chairs = eventdata.get('chairs')
            check_fields(eventdata, allowed_fields)
            check_duplicates(eventdata, 'chairs')
            event.update(**eventdata)
            event.save()
            if new_chairs:
                for chair in new_chairs:
                    if chair not in old_chairs:
                        send_role_assignment_email(chair, 'chair', event.conference)
            resp = Response(response=event.to_json(), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

class UserListAPI(Resource):
    '''returns the list of users'''

    @auth.login_required
    @check_confirmed
    # no roles required
    def get(self):
        '''returns a json list of users'''
        # List of Users, got from db
        summary_fields = ['mail', 'given_name', 'family_name']
        userlist = User.objects.all().only(*summary_fields).to_json()
        resp = Response(response=userlist, status=200, mimetype="application/json")
        return(resp)
        
class UserAPI(Resource):

    @auth.login_required
    @check_confirmed
    # no roles required
    def get (self, user_id):
        """prints the list of user or the information of a specified user"""
        public_fields = ['given_name', 'family_name', 'mail', 'sex', 'roles']
        try:
            user = User.objects.get_or_404(mail=user_id)
            user_dict = json.loads(user.to_json())
            user_dict['roles'] = user.get_roles()
            filtered_dict = {field : user_dict[field] for field in public_fields}
            resp = Response(response=json.dumps(filtered_dict), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

    # no auth required
    # no roles required
    def put(self, user_id):
        '''create a new user, hashes the password and adds it to the database'''
        allowed_fields = ['given_name', 'family_name', 'password', 'sex']
        try:
            userdata = request.get_json();
            check_fields(userdata, allowed_fields)
            userdata['mail'] = user_id
            newuser = User(**userdata)
            newuser.hash_password(userdata['password'])
            newuser.save(force_insert=True)
            token = newuser.generate_auth_token()
            send_confirmation_email(newuser.mail, token.decode('UTF-8'))
            resp = Response(response=newuser.to_json(), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp
            
    @auth.login_required
    @check_confirmed
    @allowed_roles('himself')
    def post(self, user_id):
        '''update user informations'''
        allowed_fields = ['given_name', 'family_name', 'password', 'sex']
        try:
            userdata = request.get_json();
            user = User.objects.get_or_404(mail=user_id)
            check_fields(userdata, allowed_fields)
            user.update(**userdata)
            if 'password' in userdata:
                user.hash_password(userdata['password'])
            user.save()
            resp = Response(response=user.to_json(), status=200, mimetype="application/json")
        except Exception as e:
            resp = Response(response=str(e), status=400)
        finally:
            return resp

class TokenAPI(Resource):
    @auth.login_required
    @check_confirmed
    def get(self):
        '''generate and returns a new session token'''
        token = g.user.generate_auth_token().decode("UTF-8")
        return token

class ConfirmationConfirmAPI(Resource):
    def get(self, token):
        '''URL used to confirm the user email. That is the URL + the login token sent by mail'''
        user = User.verify_auth_token(token)
        if not user:
            abort(404)
        else:
            user.confirmed = True
            user.save()
            resp = Response(response="<h1>User confirmed successfully. You can now login.</h1>", status=200, mimetype="text/html")
            return resp

class ConfirmationResendAPI(Resource):
    def get(self, user_id):
        user = User.objects.get_or_404(mail=user_id)
        if user.confirmed:
            resp = Response(response="<h1>User already confirmed.</h1>", status=400, mimetype="text/html")
        else:
            token = user.generate_auth_token()
            send_confirmation_email(user.mail, token.decode('UTF-8'))
            resp = Response(response="<h1>Confirmation re-sent, please check your email.</h1>", status=200, mimetype="text/html")
        return resp

class RecoveryTokenAPI(Resource):
    def get(self, user_id):
        user = User.objects.get_or_404(mail=user_id)
        token = user.generate_auth_token()
        send_recovery_email(user.mail, token.decode('UTF-8'))
        resp = Response(response="<h1>Recovery token sent, please check your email.</h1>", status=200, mimetype="text/html")
        return resp
        
# HELPER FUNCTIONS

@auth.verify_password
def verify_access(user_or_token, password):
    """authenticates the user"""
    #try first to auteniticate with the token
    user = User.verify_auth_token(user_or_token)
    #if it fails try to authenticate with the password
    if not user:
        try:
            user_or_token = user_or_token.lower() #accept mixed case email
            user = User.objects.get(mail=user_or_token)
        except DoesNotExist:
            user = None
        if not user or not user.verify_password(password): 
            return False
    g.user = user

    return True


mail = Mail(app)

def send_role_assignment_email(to, role, resource):
    subject = "Easyrash role assignment"
    template = """<p>Congratulation! You have been assigned as %s of %s.</p>
    <p>Remember, with great power comes great responsability.</p>
    <br>
    <p>Cheers!</p>
    """ % (role, resource)
    send_email(to, subject, template)

def send_recovery_email(to, token):
    subject = "Easyrash password recovery"
    template = """<p>Hello! Here is your password recovery token.</p>
    <p>You can use it to authenticate and change your password.</p>
    <br>
    <p>%s</p>
    <br>
    <p>Cheers!</p>
    """ % token
    send_email(to, subject, template)

def send_confirmation_email(to, token):
    subject = "Easyrash account confirmation"
    template = """<p>Welcome! Thanks for signing up. Please follow this link to activate your account:</p>
    <p><a href="http://eboli.cs.unibo.it:10000/api/confirmation/confirm/%s">eboli.cs.unibo.it:10001/api/confirmation/confirm/%s</a></p>
    <br>
    <p>Cheers!</p>
    """ % (token, token)
    send_email(to, subject, template)

def send_publishing_email(to, event, attachments):
    subject = "Accepted papers for event %s" % event
    template = """<p>The event '%s' is finalized, accepted papers to be published are in the attachments</p>
    """ % event
    send_email(to, subject, template, attachments)
    

def send_email(to, subject, template, attachments={}):
    msg = Message(
            subject,
            recipients=[to],
            html=template,
            sender=app.config['MAIL_DEFAULT_SENDER']
            )
    for attachment in attachments:
        msg.attach("%s.rash" % attachment, 'text/html', attachments[attachment])
    mail.send(msg)


def check_fields(data, allowed_fields):
    for field in data:
        if field not in allowed_fields:
            raise Exception('wrong field: %s' % field)

def check_duplicates(data, field):
    list_ = data.get(field)
    if list_:
        if len(list_) > len(set(list_)):
            raise Exception('List %s should not contain duplicates' % field)

# RESOURCES ENDPOINTS

apiobj.add_resource(PaperAPI, '/api/paper/<string:paper_id>')
apiobj.add_resource(PaperListAPI, '/api/paper')
apiobj.add_resource(PaperLockAPI, '/api/paper/<string:paper_id>/lock')
apiobj.add_resource(PaperConversionAPI, '/api/paper/<string:paper_id>/<string:fformat>')
apiobj.add_resource(FinalizeEventAPI, '/api/event/<string:event_id>/finalize')
apiobj.add_resource(EventAPI, '/api/event/<string:event_id>')
apiobj.add_resource(EventListAPI, '/api/event')
apiobj.add_resource(UserAPI, '/api/user/<string:user_id>')
apiobj.add_resource(UserListAPI, '/api/user')
apiobj.add_resource(ConfirmationConfirmAPI,'/api/confirmation/confirm/<string:token>')
apiobj.add_resource(ConfirmationResendAPI,'/api/confirmation/resend/<string:user_id>')
apiobj.add_resource(RecoveryTokenAPI,'/api/user/<string:user_id>/pwdrecovery')
apiobj.add_resource(TokenAPI,'/api/token')

