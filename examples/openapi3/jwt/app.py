#!/usr/bin/env python3
'''
Basic example of a resource server
'''

import time

import connexion
from jose import JWTError, jwt
from werkzeug.exceptions import Unauthorized
from flask import Blueprint, Flask, jsonify


JWT_ISSUER = 'com.zalando.connexion'
JWT_SECRET = 'change_this'
JWT_LIFETIME_SECONDS = 600
JWT_ALGORITHM = 'HS256'





blueprint = Blueprint("app", __name__)


def make_root_dir_name():
    return '/home/andrew/works/lab/python/connexion/examples/openapi3/jwt'



def make_endpoint():

    """
        通过模拟connexion的 operationId 来生成endpoint_name
    """
    import os
    from connexion.apis import flask_utils

    root_dir_name = make_root_dir_name()
    # endpoint_name = str(os.path.basename(__file__)).split('.')[0]
    operation_dir_name = os.path.dirname(__file__)
    operation_base_name = os.path.basename(__file__)
    operation_full_name = operation_dir_name + '/' + operation_base_name
    operation_id = str(operation_full_name).split(root_dir_name)[1]
    operation_id = str(operation_id).split('.')[0]
    operation_id = str(operation_id).split('/')[1]

    endpoint_name = flask_utils.flaskify_endpoint(operation_id)

    return endpoint_name

endpoint = make_endpoint()

print(endpoint)

@blueprint.route('/auth/<user_id>', methods=['GET'])
def generate_token(user_id):
    timestamp = _current_timestamp()
    payload = {
        "iss": JWT_ISSUER,
        "iat": int(timestamp),
        "exp": int(timestamp + JWT_LIFETIME_SECONDS),
        "sub": str(user_id),
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)



def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise Unauthorized from e

@blueprint.route('/secret', methods=['GET'])
def get_secret(user, token_info) -> str:
    return '''
    You are user_id {user} and the secret is 'wbevuec'.
    Decoded token claims: {token_info}.
    '''.format(user=user, token_info=token_info)


def _current_timestamp() -> int:
    return int(time.time())


connexion_app = connexion.FlaskApp(__name__)

# connexion_app.app.register_blueprint(blueprint)

options = {"strict_validation": True, "name": 'connexion_blueprint'}

# connexion_api = connexion_app.add_api('openapi.yaml', strict_validation=True, options=options)
connexion_api = connexion_app.add_api('openapi.yaml', options=options)

connexion_app.app.register_blueprint(blueprint)


if __name__ == '__main__':
    connexion_app.run(host='0.0.0.0', port=8080)
