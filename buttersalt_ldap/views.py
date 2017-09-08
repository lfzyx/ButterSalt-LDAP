import json
import os
import hashlib
import yaml
from base64 import encodebytes
from flask import Blueprint, render_template, current_app, flash, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, SelectMultipleField, widgets, SelectField
from wtforms.validators import InputRequired, Length, Email, Regexp, EqualTo, Optional
from flask_login import login_required
from ButterSalt import salt


class LdapAccount(FlaskForm):
    cn = StringField('姓名拼音', validators=[InputRequired('姓名拼音是必须的'), Length(1, 64),
                                         Regexp('^[A-Za-z]*$', 0,
                                                '姓名拼音只能包含拼音')], render_kw={"placeholder": "zhangsan"})
    ou = SelectField('部门')

    o = StringField('组 (可填)', validators=[Optional()])

    mail = StringField('Email', validators=[InputRequired('Email是必须的'), Length(1, 64), Email()])

    userPassword0 = PasswordField('密码', validators=[InputRequired('密码是必须的'),
                                                    EqualTo('userPassword1', message='密码必须相同.')])
    userPassword1 = PasswordField('验证密码', validators=[InputRequired('验证密码是必须的')])

    key = TextAreaField('Key (可填)', validators=[Optional()],
                        render_kw={"placeholder": "Begins with 'ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ecdsa-sha2-nistp25"
                                                  "6', 'ecdsa-sha2-nistp384', or 'ecdsa-sha2-nistp521'", "rows": "15"})

    submit = SubmitField('提交')


class MinionAccess(FlaskForm):
    minion = SelectMultipleField('主机登陆授权')
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
    ou_data = salt.execution_command_low(tgt=current_app.config.get('LDAP_SERVER'), fun='ldap3.search',
                                         args=[{'bind': {'password': current_app.config.get('LDAP_BINDPW'),
                                                         'method': 'simple',
                                                         'dn': current_app.config.get('LDAP_BINDDN')},
                                                'url': 'ldap://127.0.0.1:389'}],
                                         kwargs={'base': current_app.config.get('LDAP_BASEDN'),
                                                 'scope': 'onelevel',
                                                 'filterstr': '(objectClass=organizationalUnit)', })\
        .get(current_app.config.get('LDAP_SERVER'))

    ou_list = list()
    for n in ou_data:
        ou_list.append((ou_data.get(n).get('ou')[0], ou_data.get(n).get('ou')[0]))
    form.ou.choices = ou_list
    if form.validate_on_submit():
        def makessha(password):
            salt = os.urandom(4)
            h = hashlib.sha1(password.encode())
            h.update(salt)
            return "{SSHA}" + encodebytes(h.digest() + salt).decode()[:-1]
        cn = form.cn.data
        ou = form.ou.data
        o = form.o.data
        mail = form.mail.data
        userpassword = makessha(form.userPassword0.data)
        key = form.key.data

        salt.execution_command_low(tgt=current_app.config.get('LDAP_SERVER'), fun='ldap3.add',
                                   args=[{'bind': {'password': current_app.config.get('LDAP_BINDPW'),
                                                   'method': 'simple',
                                                   'dn': current_app.config.get('LDAP_BINDDN')},
                                          'url': 'ldap://127.0.0.1:389'}, ],
                                   kwargs={'dn': 'cn=%s,ou=%s,%s' % (cn, ou, current_app.config.get('LDAP_BASEDN')),
                                           'attributes': {'userPassword':  [userpassword],
                                                          'sn': [cn], 'mail': [mail],
                                                          'ou': [ou], 'o': [o], 'userPKCS12': [key],
                                                          'objectClass': ['inetOrgPerson',
                                                                          'organizationalPerson',
                                                                          'person', 'top']}})
        flash('Signup successfully')
        return redirect(url_for('ldap.index'))
    return render_template('ldap/signup.html', form=form)


@ldap.route('/account/<name>', methods=['GET', 'POST'])
@login_required
def account_detail(name):
    minion_list = json.loads(salt.get_accepted_keys())
    form_choices_list = list()
    for n in minion_list:
        form_choices_list.append((n, n))

    belong_minion_list = list()
    for minion in minion_list:
        text = salt.read_pillar_file('user/%s.sls' % (minion,)).get('return')[0].get(
            '/srv/pillar/user/%s.sls' % (minion,))
        text2yaml = yaml.load(text)
        if name in text2yaml.get('users'):
            belong_minion_list.append(minion)
    MinionAccess.minion = SelectMultipleField('主机登陆授权', option_widget=widgets.CheckboxInput(),
                                              widget=widgets.ListWidget(prefix_label=False), choices=form_choices_list,
                                              default=belong_minion_list)
    form = MinionAccess()

    if form.validate_on_submit():
        minion_absent_list = set(minion_list)-set(form.minion.data)
        for minion_absent in minion_absent_list:
            text = salt.read_pillar_file('user/%s.sls' % (minion_absent,)).get('return')[0].get(
                '/srv/pillar/user/%s.sls' % (minion_absent,))
            text2yaml = yaml.load(text)
            if name in text2yaml.get('users'):
                text2yaml.get('users').pop(name)
                yaml2text = yaml.dump(text2yaml)
                salt.write_pillar_file(yaml2text, 'user/%s.sls' % (minion_absent,))
                salt.execution_command_low(tgt=minion_absent, fun='user.delete', args=[name])

        for minion in form.minion.data:
            text = salt.read_pillar_file('user/%s.sls' % (minion,)).get('return')[0].get(
                '/srv/pillar/user/%s.sls' % (minion,))
            text2yaml = yaml.load(text)
            account_ldap_data = salt.execution_command_low(tgt=current_app.config.get('LDAP_SERVER'),
                                                           fun='ldap3.search',
                                                           args=[{'bind': {'password': current_app.config.get(
                                                               'LDAP_BINDPW'),
                                                                'method': 'simple',
                                                                'dn': current_app.config.get('LDAP_BINDDN')},
                                                               'url': 'ldap://127.0.0.1:389'}],
                                                           kwargs={'base': current_app.config.get('LDAP_BASEDN'),
                                                                   'scope': 'subtree',
                                                                   'filterstr': '(cn=%s)' % (name,), }).get(
                current_app.config.get('LDAP_SERVER'))
            cn = list(account_ldap_data.values())[0].get('cn')
            ou = list(account_ldap_data.values())[0].get('ou')
            text2yaml.get('users').update(
                {name: {'shell': '/bin/bash', 'fullname': cn[0], 'name': cn[0], 'groups': ou}})
            yaml2text = yaml.dump(text2yaml)
            salt.write_pillar_file(yaml2text, 'user/%s.sls' % (minion,))
        salt.execution_command_minions(tgt='*', fun='state.apply', args='user')
    return render_template('ldap/account_detail.html', form=form)
