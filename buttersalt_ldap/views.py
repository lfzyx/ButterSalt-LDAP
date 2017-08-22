from flask import Blueprint, render_template
from flask_login import login_required

ldap = Blueprint('ldap', __name__, url_prefix='/ldap', template_folder='templates')


@ldap.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('ldap/index.html')
