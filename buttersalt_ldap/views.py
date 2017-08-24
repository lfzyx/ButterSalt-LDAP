import json
from flask import Blueprint, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Length, Email, Regexp, EqualTo
from flask_login import login_required
from ButterSalt import salt


class LdapAccount(FlaskForm):
    cn = StringField('姓名拼音', validators=[InputRequired('姓名拼音是必须的'), Length(1, 64),
                                         Regexp('^[A-Za-z]*$', 0,
                                                '姓名拼音只能包含拼音')])
    ou = StringField('部门')
    email = StringField('Email', validators=[InputRequired('Email是必须的'), Length(1, 64), Email()])

    userPassword0 = PasswordField('密码', validators=[InputRequired('密码是必须的'),
                                                    EqualTo('userPassword1', message='密码必须相同.')])
    userPassword1 = PasswordField('验证密码', validators=[InputRequired('验证密码是必须的')])
    submit = SubmitField('提交')


ldap = Blueprint('ldap', __name__, url_prefix='/ldap', template_folder='templates')
__blueprint__ = ldap


@ldap.route('/', methods=['GET', 'POST'])
@login_required
def index():
    _temp=salt.execution_command_low(tgt='devops-2',fun='ldap3.search',
                                     args=[{'bind': {'password': '123456', 'method': 'simple', 'dn': 'cn=admin,dc=nodomain'},'url': 'ldap://192.168.2.81:389'}],
                                     kwargs={'base': 'dc=nodomain', })
    pretty = json.dumps(_temp, indent=4)
    return render_template('ldap/index.html', Data=pretty)


@ldap.route('/add/')
@login_required
def add():
    form = LdapAccount()
    return render_template('ldap/signup.html', form=form)
