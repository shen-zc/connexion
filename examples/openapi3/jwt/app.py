#!/usr/bin/env python3
'''
Basic example of a resource server
'''

import copy
import time

import connexion
from jose import JWTError, jwt
from werkzeug.exceptions import Unauthorized
from flask import Blueprint, Flask, jsonify


JWT_ISSUER = 'com.zalando.connexion'
JWT_SECRET = 'change_this'
JWT_LIFETIME_SECONDS = 600
JWT_ALGORITHM = 'HS256'

CONNEXION_BLUEPRINT_NAME = 'connexion_blueprint'


blueprint = Blueprint("app", __name__)


def make_root_dir_name():
    return '/home/andrew/works/lab/python/connexion/examples/openapi3/jwt'


def get_view_groups(app: Flask):
    view_functions = copy.deepcopy(app.view_functions)
    try:
        view_functions.pop('static').pop('static')
    except Exception as e:
        pass
    view_keys = view_functions.keys()
    # conn_keys = []
    # orig_keys = []
    conn_views = {}
    orig_views = {}
    for key in view_keys:
        _key = key.strip()
        if CONNEXION_BLUEPRINT_NAME in _key:
            _key = _key.lstrip(CONNEXION_BLUEPRINT_NAME)
            _key = _key.lstrip('.')
            if _key[0] == '_':
                continue
            # conn_keys.append(_key)
            conn_views[_key] = view_functions[key]
        else:
            _lkey = _key.split('.')
            _key = _lkey[0] + '_' + _lkey[1]
            # orig_keys.append(_key)
            orig_views[_key] = view_functions[key]

    return conn_views, orig_views


def check_view_funcs(app: connexion.FlaskApp):
    """
        为了在校验时获取 spec ，需要connextionApp
    """
    if isinstance(app, connexion.FlaskApp):
        _app = app.app
    elif isinstance(app, Flask):
        _app = app
    else:
        return

    conn_views, orig_views = get_view_groups(_app)
    conn_keys = set(conn_views.keys())
    orig_keys = set(orig_views.keys())

    # 检测在view中注册，但是没有在API文档中声明的视图方法
    conn__miss = orig_keys - conn_keys
    if len(conn__miss) > 0:
        print('orig_view have extra view_functions')

    # 检测在API文档中声明，但没有在view中注册的方法
    orig_miss = conn_keys - orig_keys
    if len(orig_miss) > 0:
        print('connexion_view have extra view_functions')

    cur_keys = conn_keys & orig_keys
    for key in cur_keys:
        # 检测 blueprint.route 方法注册的路由 与 API描述文件声明的路由的一致性
        view_func = orig_views[key]
        # 从view_func中获取 spec 和 vo描述进行比较
        # 主要遍历vo中的成员，是否出现在描述中
        # 除此之外，目前还不能对结构vo参数的位置和结构进行比较
        # 参数位置和结构的校验，需要在实时运行中，通过connexion的validator进行比较

    return





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

options = {"strict_validation": True, "name": CONNEXION_BLUEPRINT_NAME}

# connexion_api = connexion_app.add_api('openapi.yaml', strict_validation=True, options=options)
connexion_api = connexion_app.add_api('openapi.yaml', base_path='/fuck', options=options)

connexion_app.app.register_blueprint(blueprint)


check_view_funcs(connexion_app)

if __name__ == '__main__':
    connexion_app.run(host='0.0.0.0', port=8080)
