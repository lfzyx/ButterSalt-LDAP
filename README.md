# ButterSalt-LDAP


ButterSalt-LDAP is the LDAP Management module for  ButterSalt, not LDAP Authentication module. 

## usage

Activate ButterSalt virtual environment, install packages using pip:

`pip install buttersalt-ldap`

Edit the `ButterSalt/__init__.py` , add the following code to `create_app` function:

`from buttersalt_ldap.views import ldap`

`app.register_blueprint(ldap)`

Edit the `ButterSalt/templates/base.html` , add the following code to `<ul class="nav navbar-nav">` block:

`<li><a href="{{ url_for('ldap.index') }}"> LDAP </a></li>`
