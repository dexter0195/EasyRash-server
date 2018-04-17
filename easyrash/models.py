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

from flask_mongoengine import MongoEngine, DoesNotExist
from easyrash import app,auth
from passlib.hash import sha256_crypt as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                                  as Serializer, BadSignature, SignatureExpired)
from bs4 import BeautifulSoup
import json
import base64
import datetime


db = MongoEngine(app)

class User(db.Document):
    given_name = db.StringField(max_length=100, required=True)
    family_name = db.StringField(max_length=100, required=True)
    #this field is the 'key' for user
    mail = db.StringField(max_length=200, required=True, unique=True)
    password = db.StringField(max_length=300, required=True)
    sex = db.StringField(max_length=1, required=True, choices=('M', 'F'))
    confirmed = db.BooleanField(default=False, required=True)

    def get_roles(self):
        """returns a list of roles the user has
        the list elements are string in the format role:resource
        i.e. chair:eventid, reviewer:paperid, author:paperid"""
        roles = []
        if self.mail == 'admin@easyrash.com':
            for event in Event.objects():
                roles.append(("chair", event.acronym))
            for paper in Paper.objects():
                roles.append(("reviewer", paper.url))
            for paper in Paper.objects():
                roles.append(("author", paper.url))
        else:
            for event in Event.objects(chairs=self.mail):
                roles.append(("chair", event.acronym))
            for paper in Paper.objects(reviewers=self.mail):
                roles.append(("reviewer", paper.url))
            for paper in Paper.objects(authors=self.mail):
                roles.append(("author", paper.url))
        roles.append(("himself", self.mail))
        return roles

    def hash_password (self, password):
        """takes a string, hashes it and stores it in the password field.
        This method is called when a new user is 
        registering with the server, or when the user changes 
        the password."""
        self.password = pwd_context.encrypt(password)

    def verify_password(self,password):
        """takes a plain password as argument and returns True if the
        password is correct or False if not. This method is called 
        whenever the user provides credentials and they need to be 
        validated."""
        return pwd_context.verify(password,self.password)
    def generate_auth_token(self,expiration=604800): # expires in one week
        s = Serializer(app.config['SECRET_KEY'],expires_in=expiration)
        return s.dumps({'mail': self.mail})

    @staticmethod
    def verify_auth_token(token):
        """verifies that a token is valid"""
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            user = User.objects.get(mail=data['mail'])
        except (SignatureExpired, BadSignature, DoesNotExist):
            return None
        return user


class Event(db.Document):
    conference = db.StringField(max_length=200, required=True)
    #this field is the 'key' for event
    acronym = db.StringField(max_length=50, required=True, unique=True)
    chairs = db.ListField(db.StringField(), required=True)
    description = db.StringField(max_length=1000, required=True)
    date = db.DateTimeField(required=True)
    state = db.StringField(max_length=8, required=True, default="open")
    def get_pc_members(self):
        return list({reviewer for paper in Paper.objects(event=self.acronym) for reviewer in paper.reviewers })
    def get_submissions(self):
        return list({paper.url for paper in Paper.objects(event=self.acronym)})

class Paper(db.Document):
    title = db.StringField(max_length=200, required=True)
    authors = db.ListField(db.StringField(), required=True)
    event = db.StringField(required=True)
    #this field is the 'key' for paper
    url = db.StringField(max_length=200, required=True, unique=True)
    reviewers = db.ListField(db.StringField())
    original_text = db.StringField(required=True)
    text = db.StringField(required=True)
    #lock is implemented with a keepalive timer, if nothing happens within 1 hour it releases the lock
    lock = db.DateTimeField(default=datetime.datetime.fromtimestamp(0))
    lockowner = db.StringField(max_length=200)
    def get_lock(self, user):
        now = datetime.datetime.now()
        paper = self
        if (paper.lock < now or user.mail == paper.lockowner): 
            timeout = now + datetime.timedelta(hours=1)
            paper.update(lock = timeout, lockowner = user.mail)
            paper.save()
        else:
            raise Exception('lock already taken')
    
    def release_lock(self, user):
        #reset the lock to 0 so anyone can get it
        epoch = datetime.datetime.fromtimestamp(0)
        paper = self
        if (paper.lockowner == user.mail):
            paper.update(lock = epoch, lockowner = None)
            paper.save()
        else:
            raise Exception('you must own the lock to free it')

    def get_state(self):
        html = base64.b64decode(self.text)
        soup = BeautifulSoup(html, 'html.parser')
        review_tags = soup.find_all('script', type = 'application/ld+json')
        reviews = [json.loads(str(review_tag.string)) for review_tag in review_tags]
        rev_number = 0
        chair_decided = False
        chair_decision = None
        for review in reviews:
            if type(review) is list:
                for element in review:
                    #a script element might not be a decision/review so we need some check 
                    if type(element) is dict and element.get('@context') == 'http://vitali.web.cs.unibo.it/twiki/pub/techweb16/context.json':
                        # an element could be a comment or a final review
                        rev_type = element.get('@type')
                        if rev_type == 'decision':
                            chair_decided = True
                            try:
                                chair_decision = element['article']['eval']['status']
                                break
                            except:
                                return "Paper review corrupted"
                        elif rev_type == 'review':
                            #if the reviewer already expressed a final evaluation
                            if element['article'].get('eval'):
                                rev_number += 1
                            break
                        else:
                            pass
        all_rev_decided = rev_number == len(self.reviewers) and len(self.reviewers)!=0

        if all_rev_decided and chair_decided:
            return chair_decision
        elif all_rev_decided and not chair_decided:
            return 'pso:awaiting-decision'
        elif not all_rev_decided and not chair_decided:
            return 'pso:under-review'
        else:
            return 'Paper review corrupted'
