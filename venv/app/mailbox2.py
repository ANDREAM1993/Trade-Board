from email_validator import validate_email
from flask_mail import Mail
from flask_mail import Message
import smtplib
import email.message

class Mailbox:
    def __init__(self, app):
        self.settings = app.config
        self.receiver = None
        self.server = smtplib.SMTP(":".join([self.settings["MAIL_SERVER"], str(self.settings["MAIL_PORT"])]))
        self.message = email.message.Message()
        self.MAIL_RECEIVER = None
    def create_message_new_member(self, appname, receiver, url, deadline):
        self.receiver = receiver
        self.message['Subject'] = "{} - New Member".format(appname)
        self.message['From'] = self.settings["MAIL_DEFAULT_SENDER"]
        self.message['To'] = receiver
        self.message.add_header('Content-Type', 'text/html')
        self.message.set_payload("""
                                 <h1>New member acception</h1>
                                 <p>Navigate by URL to activate member: {}.</p>
                                 <p>Otherwise ignore this mail! URL will be expired in {} hours!</p>
                                 """.format(url, deadline))
    def create_message_reset_password(self, appname, receiver, firstname, url, deadline):
        self.receiver = receiver
        self.message['Subject'] = "{} - Reset Password".format(appname)
        self.message['From'] = self.settings["MAIL_DEFAULT_SENDER"]
        self.message['To'] = receiver
        self.message.add_header('Content-Type', 'text/html')
        self.message.set_payload("""
                                 <h1>Dear, {}!</h1>
                                 <p>Navigate by URL to reset password: {}.</p>
                                 <p>Otherwise ignore this mail! URL will be expired in {} hours!</p>
                                 """.format(firstname, url, deadline))
    def send(self):
        try:
            self.mailbox = smtplib.SMTP(":".join([self.settings["MAIL_SERVER"], str(self.settings["MAIL_PORT"])]))
            self.mailbox.starttls()
            self.mailbox.login(self.settings["MAIL_DEFAULT_SENDER"], self.settings["MAIL_PASSWORD"])
            self.mailbox.sendmail(self.settings["MAIL_DEFAULT_SENDER"], [self.receiver], self.message.as_string())
            return {
                "state": True,
                "info": {
                    "title": "Successfully Sent",
                    "text": "Your request will be processed by administrator soon"
                }
            }
        except:
            return {
                "state": False,
                "info": {
                    "title": "Request Rejection",
                    "text": "Your request has not been sent to administrator"
                }
            }