import json
import os
import hashlib
from base64 import encodebytes
from flask import Blueprint, render_template, current_app, flash, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, SelectMultipleField, widgets
from wtforms.validators import InputRequired, Length, Email, Regexp, EqualTo, Optional
from flask_login import login_required
from ButterSalt import salt


class LdapAccount(FlaskForm):
    cn = StringField('姓名拼音', validators=[InputRequired('姓名拼音是必须的'), Length(1, 64),
                                         Regexp('^[A-Za-z]*$', 0,
                                                '姓名拼音只能包含拼音')])
    ou = StringField('部门')
    mail = StringField('Email', validators=[InputRequired('Email是必须的'), Length(1, 64), Email()])

    userPassword0 = PasswordField('密码', validators=[InputRequired('密码是必须的'),
                                                    EqualTo('userPassword1', message='密码必须相同.')])
    userPassword1 = PasswordField('验证密码', validators=[InputRequired('验证密码是必须的')])

    key = TextAreaField('Key', validators=[Optional()],
                        render_kw={"placeholder": "Begins with 'ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ecdsa-sha2-nistp25"
                                                  "6', 'ecdsa-sha2-nistp384', or 'ecdsa-sha2-nistp521'", "rows": "15"})

    submit = SubmitField('提交')


class MinionAccess(FlaskForm):
    minion = SelectMultipleField('主机登陆授权', option_widget=widgets.CheckboxInput(),
                                 widget=widgets.ListWidget(prefix_label=False))
    submit = SubmitField('提交')


ldap = Blueprint('ldap', __name__, url_prefix='/ldap', template_folder='templates')
__blueprint__ = ldap


@ldap.route('/', methods=['GET', 'POST'])
@login_required
def index():
    account = salt.execution_command_low(tgt=current_app.config.get('LDAP_SERVER'), fun='ldap3.search',
                                            args=[{'bind': {'password': current_app.config.get('LDAP_BINDPW'),
                                                            'method': 'simple',
                                                            'dn': current_app.config.get('LDAP_BINDDN')},
                                                   'url': 'ldap://127.0.0.1:389'}],
                                            kwargs={'base': current_app.config.get('LDAP_BASEDN'),
                                                    'scope': 'subtree',
                                                    'filterstr': '(objectClass=organizationalPerson)', })\
        .get(current_app.config.get('LDAP_SERVER'))
    return render_template('ldap/index.html', Data=account)


@ldap.route('/signup/', methods=['GET', 'POST'])
@login_required
def signup():
    """ salt.modules.ldap3.add

    """
    form = LdapAccount()
    if form.validate_on_submit():
        def makessha(password):
            salt = os.urandom(4)
            h = hashlib.sha1(password.encode())
            h.update(salt)
            return "{SSHA}" + encodebytes(h.digest() + salt).decode()[:-1]
        cn = form.cn.data
        ou = form.ou.data
        mail = form.mail.data
        userpassword = makessha(form.userPassword0.data)
        key = form.key.data

        salt.execution_command_low(tgt=current_app.config.get('LDAP_SERVER'), fun='ldap3.add',
                                   args=[{'bind': {'password': current_app.config.get('LDAP_BINDPW'),
                                                   'method': 'simple',
                                                   'dn': current_app.config.get('LDAP_BINDDN')},
                                          'url': 'ldap://127.0.0.1:389'}, ],
                                   kwargs={'dn': 'cn=%s,ou=%s,dc=nodomain' % (cn, ou),
                                           'attributes': {'userPassword':  [userpassword],
                                                          'sn': [cn], 'mail': [mail],
                                                          'ou': [ou], 'userPKCS12': [key],
                                                          'objectClass': ['inetOrgPerson',
                                                                          'organizationalPerson',
                                                                          'person', 'top']}})
        flash('Signup successfully')
        return redirect(url_for('ldap.index'))
    return render_template('ldap/signup.html', form=form)


@ldap.route('/account/<name>', methods=['GET', 'POST'])
@login_required
def account_detail(name):
    form = MinionAccess()
    tgt_list = salt.get_accepted_keys()
    _list = list()
    for n in json.loads(tgt_list):
        _list.append((n, n))
    form.minion.choices = _list
    if form.validate_on_submit():
        print(form.minion.data)
    return render_template('ldap/account_detail.html', form = form)
