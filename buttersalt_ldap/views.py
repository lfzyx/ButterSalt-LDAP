from flask import Blueprint, render_template
from flask_login import login_required
from ButterSalt import salt

ldap = Blueprint('ldap', __name__, url_prefix='/ldap', template_folder='templates')
__blueprint__ = ldap


@ldap.route('/', methods=['GET', 'POST'])
@login_required
def index():

    return render_template('ldap/index.html')
