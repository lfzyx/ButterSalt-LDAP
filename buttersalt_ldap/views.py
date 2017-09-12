import json
import os
import hashlib
import yaml
from base64 import encodebytes
from flask import Blueprint, render_template, flash, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, SelectMultipleField, widgets, SelectField
from wtforms.validators import InputRequired, Length, Email, Regexp, EqualTo, Optional, DataRequired
from flask_login import login_required
from ButterSalt import salt
from .ldap3 import Ldap3


class LdapAccount(FlaskForm):
    cn = StringField('姓名拼音', validators=[InputRequired('姓名拼音是必须的'), Length(1, 64),
                                         Regexp('^[A-Za-z]*$', 0,
                                                '姓名拼音只能包含拼音')], render_kw={"placeholder": "zhangsan"})
    ou = SelectField('部门', validators=[DataRequired()], default=None)

    o = StringField('组 (可填)', validators=[Optional()])

    mail = StringField('Email', validators=[InputRequired('Email是必须的'), Length(1, 64), Email()])

    userPassword0 = PasswordField('密码', validators=[InputRequired('密码是必须的'),
                                                    EqualTo('userPassword1', message='密码必须相同.')])
    userPassword1 = PasswordField('验证密码', validators=[InputRequired('验证密码是必须的')])

    key = TextAreaField('Key (可填)', validators=[Optional()],
                        render_kw={"placeholder": "Begins with 'ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ecdsa-sha2-nistp25"
                                                  "6', 'ecdsa-sha2-nistp384', or 'ecdsa-sha2-nistp521'", "rows": "15"})

    submit = SubmitField('提交')


class LdapAccountEdit(FlaskForm):
    ou = SelectField('部门')
    o = StringField('组 (可填)', validators=[Optional()])
    userPassword0 = PasswordField('密码', validators=[Optional(),
                                                    EqualTo('userPassword1', message='密码必须相同.')],
                                  render_kw={"placeholder": "**********"})
    userPassword1 = PasswordField('验证密码', validators=[Optional(),
                                                    EqualTo('userPassword0', message='密码必须相同.')],
                                  render_kw={"placeholder": "**********"})
    key = TextAreaField('Key (可填)', validators=[Optional()],
                        render_kw={"placeholder": "Begins with 'ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ecdsa-sha2-nistp25"
                                                  "6', 'ecdsa-sha2-nistp384', or 'ecdsa-sha2-nistp521'", "rows": "15"})
    minion = SelectMultipleField('主机登陆授权')
    submit = SubmitField('提交')


ldap = Blueprint('ldap', __name__, url_prefix='/ldap', template_folder='templates')


@ldap.route('/', methods=['GET', 'POST'])
@login_required
def index():
    ldap3 = Ldap3()
    accounts = ldap3.search(scope='subtree', filterstr='(objectClass=organizationalPerson)')
    return render_template('ldap/index.html', Data=accounts)


@ldap.route('/signup/', methods=['GET', 'POST'])
@login_required
def signup():
    """ salt.modules.ldap3.add

    """
    form = LdapAccount()
    ldap3 = Ldap3()
    ou_data = ldap3.search(scope='onelevel', filterstr='(objectClass=organizationalUnit)')
    ou_list = [(ou_data.get(n).get('ou')[0], ou_data.get(n).get('ou')[0]) for n in ou_data]
    ou_list.append((None, ''))
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
        ldap3.add(cn=cn, ou=ou, o=o, userpassword=userpassword, mail=mail, key=key)
        flash('Signup successfully')
        return redirect(url_for('ldap.index'))
    return render_template('ldap/signup.html', form=form)


@ldap.route('/account/<name>', methods=['GET', 'POST'])
@login_required
def account_detail(name):
    ldap3 = Ldap3()
    account = ldap3.search(scope='subtree', filterstr='(cn=%s)' % (name,))

    minion_list = json.loads(salt.get_accepted_keys())
    belong_minion_list = list()
    for minion in minion_list:
        text = salt.read_pillar_file('user/%s.sls' % (minion,)).get('return')[0].get(
            '/srv/pillar/user/%s.sls' % (minion,))
        text2yaml = yaml.load(text)
        if name in text2yaml.get('users'):
            belong_minion_list.append(minion)

    return render_template('ldap/account_detail.html', Data=list(account.values()),
                           belong_minion_list=belong_minion_list, minion_list=minion_list)


@ldap.route('/account/<name>/edit', methods=['GET', 'POST'])
@login_required
def account_edit(name):
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
    LdapAccountEdit.minion = SelectMultipleField('主机登陆授权', option_widget=widgets.CheckboxInput(),
                                                 widget=widgets.ListWidget(prefix_label=False),
                                                 choices=form_choices_list,
                                                 default=belong_minion_list)

    ldap3 = Ldap3()
    ou_data = ldap3.search(scope='onelevel', filterstr='(objectClass=organizationalUnit)')
    ou_list = [(ou_data.get(n).get('ou')[0], ou_data.get(n).get('ou')[0]) for n in ou_data]
    account = ldap3.search(scope='subtree', filterstr='(cn=%s)' % (name,))
    default_ou = list(account.values())[0].get('ou')[0]
    try:
        default_o = list(account.values())[0].get('o')[0]
    except:
        default_o = ''
    try:
        default_key = list(account.values())[0].get('userPKCS12')[0]
    except:
        default_key = ''

    LdapAccountEdit.ou = SelectField('部门', choices=ou_list, default=default_ou)
    form = LdapAccountEdit()

    if form.validate_on_submit():

        def makessha(password):
            salt = os.urandom(4)
            h = hashlib.sha1(password.encode())
            h.update(salt)
            return "{SSHA}" + encodebytes(h.digest() + salt).decode()[:-1]

        ldap3.modify(dn=list(account.keys())[0], op='replace', attr='ou', vals=form.ou.data)
        if form.userPassword0.data:
            userpassword = makessha(form.userPassword0.data)
            ldap3.modify(dn=list(account.keys())[0], op='replace', attr='userPassword',vals=userpassword)
        if form.key.data:
            ldap3.modify(dn=list(account.keys())[0], op='replace', attr='userPKCS12', vals=form.key.data)
        if form.o.data:
            ldap3.modify(dn=list(account.keys())[0], op='replace', attr='o', vals=form.o.data)

        minion_absent_list = set(minion_list) - set(form.minion.data)
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
            text2yaml.get('users').update(
                {name: {'shell': '/bin/bash', 'fullname': name, 'name': name, 'groups': [form.ou.data]}})
            yaml2text = yaml.dump(text2yaml)
            salt.write_pillar_file(yaml2text, 'user/%s.sls' % (minion,))
            salt.execution_command_minions(tgt=minion, fun='ssh.set_auth_key', kwargs={'user':name, 'key':form.key.data.split()[1]})

        salt.execution_command_minions(tgt='*', fun='state.apply', args='user')
        return redirect(url_for('ldap.account_detail', name=name))
    return render_template('ldap/account_edit.html', form=form, default_o=default_o, default_key=default_key)


@ldap.route('/account/<name>/delete', methods=['GET', 'POST'])
@login_required
def account_delete(name):
    ldap3 = Ldap3()
    account = ldap3.search(scope='subtree', filterstr='(cn=%s)' % (name,))
    ldap3.delete(dn=list(account.keys())[0])
    minion_list = json.loads(salt.get_accepted_keys())
    for minion in minion_list:
        text = salt.read_pillar_file('user/%s.sls' % (minion,)).get('return')[0].get(
            '/srv/pillar/user/%s.sls' % (minion,))
        text2yaml = yaml.load(text)
        if name in text2yaml.get('users'):
            text2yaml.get('users').pop(name)
            yaml2text = yaml.dump(text2yaml)
            salt.write_pillar_file(yaml2text, 'user/%s.sls' % (minion,))
            salt.execution_command_low(tgt=minion, fun='user.delete', args=[name])
    return redirect(url_for('ldap.index'))
