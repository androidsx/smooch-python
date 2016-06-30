# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import logging
import jwt
import json
import os
import requests

from mimetypes import MimeTypes

log = logging.getLogger(__name__)


class Smooch:
    ALGORITHM = 'HS256'

    class APIError(Exception):
        def __init__(self, response):
            self.response = response

        def __str__(self):
            return str(self.response)

    def __init__(self, key_id, secret):
        self.key_id = key_id
        self.secret = secret
        self.jwt_token = jwt.encode({'scope': 'app'}, secret, algorithm=self.ALGORITHM, headers={"kid": key_id})

    @staticmethod
    def jwt_for_user(key_id, secret, user_id):
        return jwt.encode({'scope': 'appUser', 'userId': user_id}, secret, algorithm=Smooch.ALGORITHM,
                          headers={"kid": key_id})

    def user_jwt(self, user_id):
        return self.jwt_for_user(self.key_id, self.secret, user_id)

    def ask(self, endpoint, data, method='get', files=None):
        url = "https://api.smooch.io/v1/{0}".format(endpoint)

        if method == 'get':
            caller_func = requests.get
        elif method == 'post':
            caller_func = requests.post
        elif method == 'put':
            caller_func = requests.put
        elif method == 'delete':
            caller_func = requests.delete

        headers = self.headers
        if files:
            headers.pop('content-type')
        elif method == 'put' or method == 'post':
            data = json.dumps(data)

        log.debug('Asking method: %s', caller_func)
        log.debug('Asking url: %s', url)
        log.debug('Asking headers: %s', headers)
        log.debug('Asking data: %s', data)
        log.debug('Asking files: %s', files)

        response = caller_func(url=url, headers=headers, data=data, files=files)

        if response.status_code in [200, 201]:
            return response
        else:
            raise Smooch.APIError(response)

    def post_message(self, user_id, message, sent_by_maker=False):
        role = "appUser"
        if sent_by_maker:
            role = "appMaker"

        data = {"text": message, "role": role}
        return self.ask('appusers/{0}/conversation/messages'.format(user_id), data, 'post')

    def post_media(self, user_id, file_path, sent_by_maker=False):
        role = "appUser"
        if sent_by_maker:
            role = "appMaker"

        data = {"role": role}

        mime = MimeTypes()
        mime_type, _ = mime.guess_type(file_path)

        file_name = os.path.basename(file_path)
        files = {'source': (file_name, open(file_path, 'rb'), mime_type)}

        url = 'appusers/{0}/conversation/images'.format(user_id)

        return self.ask(url, data, 'post', files)

    def get_user(self, user_id):
        """
        Retrieve a specific app user.
        Args:
            user_id (str): A unique identifier for the app user.
        """
        return self.ask('appusers/{0}'.format(user_id), {}, 'get')

    def update_user(self, user_id, data=None):
        """
        Update an app user’s basic profile information
        Args:
            user_id (int): A unique identifier for the app user.
            data (dict, optional): Can contain `givenName`, `surname`, `email`, `signUpAt`, `properties` values
        """
        if data is None:
            data = {}
        return self.ask('appusers/{0}'.format(user_id), data, 'put')

    def init_user(self, device_id, user_id=None):
        """
        This API is called when the app is first loaded.
        Args:
            device (str): A descriptor of the user’s device.
            user_id (str, optional): A unique identifier for the app user.
        """
        data = {
            "device": {
                "id": device_id,
                "platform": "other"
            }
        }
        if user_id:
            data.update({'userId': user_id})
        return self.ask('init', data, 'post')

    def precreate_user(self, user_id, data=None):
        """
        Pre-Create App User
        Args:
            user_id (int): A unique identifier for the app user.
            data (dict, optional): Can contain `givenName`, `surname`, `email`, `signUpAt`, `properties` values
        """
        if data is None:
            data = {}

        data.update({"userId": user_id})

        return self.ask('appusers', data, 'post')

    def get_webhooks(self):
        """
        List webhooks
        """
        return self.ask('webhooks', {}, 'get')

    def make_webhook(self, target, triggers=None):
        """
        Create webhook
        Args:
            target (str): URL to be called when the webhook is triggered.
            triggers (array, optional): An array of triggers you wish to have the webhook listen to. Default trigger is message.
        """
        if triggers is None:
            triggers = ['message']

        return self.ask('webhooks', {"target": target, "triggers": triggers}, 'post')

    def get_webhook(self, webhook_id):
        """
        Get webhook
        """
        return self.ask('webhooks/{0}'.format(webhook_id), {}, 'get')

    def update_webhook(self, webhook_id, target, triggers):
        """
        Update webhook
        Args:
            webhook_id (str): webhook ID.
            target (str): URL to be called when the webhook is triggered.
            triggers (array, optional): An array of triggers you wish to have the webhook listen to. Default trigger is message.
        """
        return self.ask('webhooks/{0}'.format(webhook_id), {"target": target, "triggers": triggers}, 'put')

    def delete_webhook(self, webhook_id):
        """
        Deletes the specified webhook.
        Args:
            webhook_id (str): webhook ID
        """
        return self.ask('webhooks/{0}'.format(webhook_id), {}, 'delete')

    def delete_all_webhooks(self):
        """
        Deletes all webhook using get_webhooks method.
        """
        webhooks_response = self.get_webhooks()
        webhooks = webhooks_response.json()['webhooks']

        responses = []
        for webhook in webhooks:
            dr = self.delete_webhook(webhook['_id'])
            responses.append(dr)

        return responses

    def ensure_webhook_exists(self, trigger, webhook_url):
        log.debug("Ensuring that webhook exist: %s; %s", trigger, webhook_url)
        r = self.get_webhooks()
        data = r.json()

        message_webhook_id = False
        message_webhook_needs_updating = False
        webhook_secret = None

        for value in data["webhooks"]:
            if trigger in value["triggers"]:
                message_webhook_id = value["_id"]
                webhook_secret = value["secret"]
                if value["target"] != webhook_url:
                    message_webhook_needs_updating = True
                break

        log.debug("message_webhook_id: %s", message_webhook_id)
        log.debug("message_webhook_needs_updating: %s", message_webhook_needs_updating)
        if not message_webhook_id:
            log.debug("Creating webhook")
            r = self.make_webhook(webhook_url, [trigger])
            data = r.json()
            message_webhook_id = data["webhook"]["_id"]
            webhook_secret = data["webhook"]["secret"]

        if message_webhook_needs_updating:
            log.debug("Updating webhook")
            self.update_webhook(message_webhook_id, webhook_url, [trigger])

        return message_webhook_id, webhook_secret

    @property
    def headers(self):
        return {
            'Authorization': 'Bearer {0}'.format(self.jwt_token),
            'content-type': 'application/json'
        }
