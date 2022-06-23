from flask import Flask
from flask import flash
from flask import render_template
from flask import request
from flask import session
from flask import redirect
from flask import abort
from datetime import datetime
from functools import wraps
from configs import *
from database import *
from mailbox2 import *
from security import *
from validator import *
import logging, os

###############
# APPLICATION #
###############

app = Flask(__name__)
app.config.from_object(Development)
logging.basicConfig(filename="{}.log".format(datetime.now().strftime("%d-%m-%Y")), level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

###########
# MODULES #
###########

validator = Validator()
db = Database(app.config)
mailbox = Mailbox(app)

##########
# ERRORS #
##########

@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def view_errors(error):
    if request.url_rule:
        app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), str(error.code)]))
    else:
        app.logger.info("; ".join([request.remote_addr.strip(), str(error.code)]))
    return render_template("error.html", e=error)

##################
# ACCESS CONTROL #
##################
                                      
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        db.connect()
        state = db.sessions_validate(session.get("token", None))
        print(state)
        if not state["state"]:
            db.disconnect()
            flash(state["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), state["info"]["title"], state["info"]["text"]]))
            return redirect("/authentication/login")
        return f(*args, **kwargs)
    return decorated_function
def login_not_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        db.connect()
        state = db.sessions_validate(session.get("token", None))
        print(state)
        if state["state"]:
            db.disconnect()
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip()]))
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function

##################
# AUTHENTICATION #
##################
@app.route("/authentication/signup")
@login_not_required
def view_signup():
    try:
        return render_template("authentication/signup.html")
    except:
        abort(404)
@app.route("/authentication/login")
@login_not_required
def view_login():
    try:
        return render_template("authentication/login.html")
    except:
        abort(404)
@app.route("/authentication/password/reset")
@login_not_required
def view_password_reset():
    try:
        return render_template("authentication/password/reset.html")
    except:
        abort(404)
@app.route("/authentication/password/setup/<string:token>")
@login_not_required
def view_password_setup(token):
    try:
        return render_template("authentication/password/setup.html", token=token)
    except:
        abort(404)
@app.route("/authentication/signup/send", methods=["POST"])
@login_not_required
def controller_signup():
    try:
        firstname = validator.validate_firstname(request.form.get("firstname", ""))
        if not firstname["state"]:
            flash(firstname["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), firstname["info"]["title"], firstname["info"]["text"]]))
            return redirect(request.referrer)
        lastname = validator.validate_lastname(request.form.get("lastname", ""))
        if not lastname["state"]:
            flash(lastname["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), lastname["info"]["title"], lastname["info"]["text"]]))
            return redirect(request.referrer)
        username = validator.validate_username(request.form.get("username", ""))
        if not username["state"]:
            flash(username["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), username["info"]["title"], username["info"]["text"]]))
            return redirect(request.referrer)
        email = validator.validate_email(request.form.get("email", ""))
        if not email["state"]:
            flash(email["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), email["info"]["title"], email["info"]["text"]]))
            return redirect(request.referrer)
        password = validator.validate_password(request.form.get("password", ""))
        if not password["state"]:
            flash(password["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), password["info"]["title"], password["info"]["text"]]))
            return redirect(request.referrer)
        confirmation_password = validator.validate_password_x2(password["password"],
                                                               request.form.get("confirmation_password", ""))
        if not confirmation_password["state"]:
            flash(confirmation_password["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), confirmation_password["info"]["title"], confirmation_password["info"]["text"]]))
            return redirect(request.referrer)
        password = string_safe(password["password"])
        db.connect()
        constants = db.constants_get()
        if not constants["state"]:
            flash(constants["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), constants["info"]["title"], constants["info"]["text"]]))
            db.disconnect()
            return redirect(request.referrer)
        application = db.application_get()
        if not application["state"]:
            flash(application["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), application["info"]["title"], application["info"]["text"]]))
            db.disconnect()
            return redirect(request.referrer)
        #print(username["username"], password["hash"], email["email"], firstname["firstname"], lastname["lastname"])
        token = db.accounts_add(username["username"], password["hash"], email["email"], firstname["firstname"], lastname["lastname"])
        if not token["state"]:
            flash(token["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), token["info"]["title"], token["info"]["text"]]))
            return redirect(request.referrer)
        db.disconnect()
        mailbox.create_message_new_member(application["application"]["title"],
                                          app.config["MAIL_USERNAME"],
                                          "{}authentication/password/activate/{}".format(request.host_url, token["token"]),
                                          constants["constants"]["deadline_activation"] // 3600)
        #print("{}authentication/password/setup/{}".format(request.host_url, token["token"]))
        message = mailbox.send()
        if not message["state"]:
            flash(message["info"], "danger")
            app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), message["info"]["title"], message["info"]["text"]]))
            return redirect(request.referrer)
        flash(message["info"], "success")
        app.logger.info("; ".join([request.remote_addr.strip(), request.url_rule.rule.strip(), request.url_rule.endpoint.strip(), message["info"]["title"], message["info"]["text"]]))
        return redirect("/authentication/login")
    except:
        abort(500)
@app.route("/authentication/password/activate/<string:token>", methods=["GET"])
def controller_authentication_activate(token):
    try:
        db.connect()
        activation = db.accounts_enable(token)
        db.disconnect()
        if not activation["state"]:
            flash(activation["info"], "danger")
        else:
            flash(activation["info"], "success")
        return redirect("/authentication/login")
    except:
        abort(500)
@app.route("/authentication/login/send", methods=["POST"])
@login_not_required
def controller_login():
    
        username = validator.validate_username(request.form.get("username", ""))
        if not username["state"]:
            flash(username["info"], "danger")
            return redirect(request.referrer)
        password = validator.validate_password(request.form.get("password", ""))
        if not password["state"]:
            flash(password["info"], "danger")
            return redirect(request.referrer)
        password = string_safe(password["password"])
        db.connect()
        token = db.sessions_init(username["username"], password["hash"])
        #print(token)
        db.disconnect()
        if not token["state"]:
            flash(token["info"], "danger")
            return redirect(request.referrer)
        session["token"] = token["token"]
        return redirect("/")
    
        abort(500)
@app.route("/authentication/logout")
@login_required
def controller_logout():
    try:
        db.connect()
        s_session = db.sessions_complete(session.get("token", None))
        db.disconnect()
        if not s_session["state"]:
            flash(s_session["info"], "danger")
            return redirect(request.referrer)
        session.clear()
        return redirect("/authentication/login")
    except:
        abort(500)
@app.route("/authentication/password/reset/send", methods=["POST"])
@login_not_required
def controller_password_reset():
    try:
        email = validator.validate_email(request.form.get("email", ""))
        if not email["state"]:
            flash(email["info"], "danger")
            return redirect(request.referrer)
        #print(email)
        db.connect()
        constants = db.constants_get()
        if not constants["state"]:
            flash(constants["info"], "danger")
            return redirect(request.referrer)
        application = db.application_get()
        if not application["state"]:
            flash(application["info"], "danger")
            return redirect(request.referrer)
        r_request = db.requests_password_add(email["email"])
        db.disconnect()
        if not r_request["state"]:
            flash(r_request["info"], "danger")
            return redirect(request.referrer)
        mailbox.create_message_reset_password(application["application"]["title"],
                                              email["email"],
                                              r_request["firstname"],
                                              "{}authentication/password/setup/{}".format(request.host_url, r_request["token"]),
                                              constants["constants"]["deadline_reset"] // 3600)
        #print("{}authentication/password/setup/{}".format(request.host_url, r_request["token"]))
        message = mailbox.send()
        print(mailbox.message, message)
        if not message["state"]:
            flash(message["info"], "danger")
            return redirect(request.referrer)
        flash(message["info"], "success")
        return redirect("/authentication/login")
    except:
        abort(500)
@app.route("/authentication/password/setup/send", methods=["POST"])
@login_not_required
def controller_password_setup():
    try:
        password = validator.validate_password(request.form.get("new-password", ""))
        print(password)
        if not password["state"]:
            flash(password["info"], "danger")
            return redirect(request.referrer)
        confirmation_password = validator.validate_password_x2(password["password"],
                                                               request.form.get("confirmation-password", ""))
        if not confirmation_password["state"]:
            flash(confirmation_password["info"], "danger")
            return redirect(request.referrer)
        password = string_safe(password["password"])
        db.connect()
        application = db.application_get()
        if not application["state"]:
            db.disconnect()
            flash(application["info"], "danger")
            return redirect(request.referrer)
        new_password = db.requests_password_delete(request.form.get("token", ""), password["hash"])
        db.disconnect()
        if not new_password["state"]:
            flash(new_password["info"], "danger")
            return redirect(request.referrer)
        flash(new_password["info"], "success")
        return redirect("/authentication/login")
    except:
        abort(500)

#############
# DASHBOARD #
#############


@app.route("/")
@app.route("/dashboard")
@login_required
def view_dashboard():
    constants = db.constants_get()
    if not constants["state"]:
        db.disconnect()
        flash(constants["info"], "danger")
        return redirect("/authentication/logout")
    account = db.accounts_get(token=session.get("token", None))
    
    if not account["state"]:
        db.disconnect()
        flash(account["info"], "danger")
        return redirect("/authentication/logout")
    notifications = db.notifications_get()
    #print(notifications)
    if not notifications["state"]:
        db.disconnect()
    limits = db.limits_get()
    #print(limits)
    if not limits["state"]:
        db.disconnect()
        flash(limits["info"], "danger")
        return redirect("/authentication/logout")
    timeframes = db.timeframes_get()
    #print(timeframes)
    if not timeframes["state"]:
        db.disconnect()
        flash(limits["info"], "danger")
        return redirect("/authentication/logout")
    if constants["constants"]["mode"] == "table":
        table = db.table_get(account["account"]["role"] == "admin")
        print(table)
        db.disconnect()
        return render_template("dashboard/table.html", page="dashboard", updatedAt=datetime.now().strftime("%H:%M:%S"), limits=limits, timeframes=timeframes, table=table, constants=constants, account=account, notifications=notifications)
    if constants["constants"]["mode"] == "chart":
        charts = db.charts_get()
        print(charts)
        reports = db.reports_get()
        if not reports["state"]:
            db.disconnect()
            flash(reports["info"], "danger")
            return redirect("/authentication/logout")
        chart = db.chart_get(account["account"]["role"] == "admin")
        print(chart)
        db.disconnect()
        return render_template("dashboard/chart.html", page="dashboard", updatedAt=datetime.now().strftime("%H:%M:%S"), charts=charts, reports=reports, limits=limits, timeframes=timeframes, chart=chart, constants=constants, account=account, notifications=notifications)

@app.route("/feedback")
@login_not_required
def view_contact_us():
    try:
        db.connect()
        constants = db.constants_get()
        if not constants["state"]:
            db.disconnect()
            flash(constants["info"], "danger")
            return redirect("/authentication/logout")
        input(constants)
        account = db.accounts_get(token=session.get("token",None))
        if not account["state"]:
            db.disconnect()
            flash(account["info"], "danger")
            return redirect("/authentication/logout")
        input(account)
        return render_template("dashboard/feedback.html", page="feedback", constants=constants, account=account)
    except:
        abort(404)

@app.route("/dashboard/select-limit/<int:limit>", methods=["GET"])
@login_required
def controller_limits(limit):
    try:
        limit = validator.validate_limit(limit)
        if not limit["state"]:
            flash(limit["info"], "danger")
            return redirect(request.referrer)
        db.connect()
        new_limit = db.limits_update(limit["limit"])
        print(new_limit)
        if not new_limit["state"]:
            db.disconnect()
            flash(new_limit["info"], "danger")
        db.disconnect()
        return redirect(request.referrer)
    except:
        abort(500)
@app.route("/dashboard/select-timeframe/<int:timeframe>", methods=["GET"])
@login_required
def controller_timeframes(timeframe):
    try:
        timeframe = validator.validate_timeframe(timeframe)
        if not timeframe["state"]:
            flash(timeframe["info"], "danger")
            return redirect(request.referrer)
        db.connect()
        new_timeframe = db.timeframes_update(timeframe["timeframe"])
        print(new_timeframe)
        if not new_timeframe["state"]:
            db.disconnect()
            flash(new_timeframe["info"], "danger")
        db.disconnect()
        return redirect(request.referrer)
    except:
        abort(500)
@app.route("/dashboard/select-mode/<string:mode>", methods=["GET"])
@login_required
def controller_modes(mode):
    try:
        mode = validator.validate_mode(mode)
        print(mode)
        if not mode["state"]:
            flash(mode["info"], "danger")
            return redirect(request.referrer)
        db.connect()
        new_mode = db.modes_update(mode["mode"])
        print(new_mode)
        if not new_mode["state"]:
            db.disconnect()
            flash(new_mode["info"], "danger")
        db.disconnect()
        return redirect(request.referrer)
    except:
        abort(500)
@app.route("/dashboard/select-chart/<string:chart>", methods=["GET"])
@login_required
def controller_chart(chart):
    try:
        chart = validator.validate_chart(chart)
        print(chart)
        if not chart["state"]:
            flash(chart["info"], "danger")
            return redirect(request.referrer)
        db.connect()
        new_chart = db.charts_update(chart["chart"])
        print(new_chart)
        if not new_chart["state"]:
            db.disconnect()
            flash(new_chart["info"], "danger")
        db.disconnect()
        return redirect(request.referrer)
    except:
        abort(500)
@app.route("/dashboard/select-report/<string:report>", methods=["GET"])
@app.route("/dashboard/select-report/<string:report>/<string:type>", methods=["GET"])
@login_required
def controller_report(report,type=None):
    try:
        report = validator.validate_report(report)
        print(report)
        if not report["state"]:
            flash(report["info"], "danger")
            return redirect(request.referrer)
        db.connect()
        new_report = db.reports_update(report["report"],type)
        print(new_report)
        if not new_report["state"]:
            db.disconnect()
            flash(new_report["info"], "danger")
        db.disconnect()
        return redirect(request.referrer)
    except:
        abort(500)
@app.route("/feedback/send", methods=["POST"])
@login_not_required
def controller_contact_us():
    try:
        username = validator.validate_username(request.form.get("username", ""))
        if not username["state"]:
            flash(username["info"], "danger")
            return redirect(request.referrer)
        title = validator.validate_feedback_title(request.form.get("title", ""))
        if not title["state"]:
            flash(title["info"], "danger")
            return redirect(request.referrer)
        text = validator.validate_feedback_text(request.form.get("text", ""))
        if not text["state"]:
            flash(text["info"], "danger")
            return redirect(request.referrer)
        db.connect()
        new_feedback = db.feedbacks_add(username["username"], title["title"], text["text"])
        print(new_feedback)
        if not new_feedback["state"]:
            db.disconnect()
            flash(new_feedback["info"], "danger")
        db.disconnect()
        flash({"title": "Successfully Sent", "text": "Your feedback has been received. Admisitrator will contact with you soon!"}, "success")
        return redirect(request.referrer)
    except:
        abort(500)

@app.route("/dashboard/chart/select-axis/<string:axis>/<string:title>")
@login_required
def controller_axis(axis,title):
    try:
        print(axis,title)
        db.connect()
        new_axis = db.axis_update(axis,title)
        print(new_axis)
        if not new_axis["state"]:
            db.disconnect()
            flash(new_axis["info"], "danger")
        db.disconnect()
        return redirect(request.referrer)
    except:
        abort(500)

#############
# SETTINGS #
#############


@app.route("/settings")
@login_required
def view_settings():
    try:
        return redirect("/settings/accounts")
    except:
        abort(404)
@app.route("/settings/<string:table>")
@login_required
def view_settings_table(table):
    
        db.connect()
        state = db.sessions_validate(session.get("token", None))
        if not state["state"]:
            db.disconnect()
            flash(state["info"], "danger")
            return redirect("/authentication/login")
        account = db.accounts_get(token=session.get("token", None))
        if not account["state"]:
            db.disconnect()
            flash(account["info"], "danger")
            return redirect("/authentication/logout")
        if account["account"]["role"] != "admin":
            db.disconnect()
            flash({
                "title": "Access Restriction",
                "text": "Settings are available for administrators (only)!"
            }, "danger")
            return redirect("/")
        #print(account)
        notifications = db.notifications_get(True)
        if not notifications["state"]:
            db.disconnect()
            flash(notifications["info"], "danger")
            return redirect("/")
        #print(notifications)
        constants = db.constants_get()
        if not constants["state"]:
            db.disconnect()
            flash(constants["info"], "danger")
            return redirect("/")
        #print(notifications)
        settings = db.settings_get(table)
        db.disconnect()
        #print(settings)
        if not settings["state"]:
            db.disconnect()
            flash(settings["info"], "danger")
            return redirect("/")
        return render_template("settings/{}.html".format(table), table=table, settings=settings, account=account, notifications=notifications, constants=constants)
    
@app.route("/settings/update/<string:table>/<string:field>/<string:value>/<string:primary>/<string:key>", methods=["GET"])
@login_required
def controller_settings(table, field, value, primary, key):
    try:
        print("xxxxxxxxxxxxxxxxxxx",table, field, value, primary, key)
        db.connect()
        update = db.settings_update(table, field, value, primary, key)
        print(update)
        if not update["state"]:
            db.disconnect()
            flash(update["info"], "danger")
        db.disconnect()
        return redirect(request.referrer)
    except:
        abort(500)

@app.route("/settings/spider/<string:table>/<string:state>", methods=["GET"])
@login_required
def controller_spiders(table, state):
    pass

