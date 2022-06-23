from email_validator import validate_email
from json import load
from re import match


class Validator:
    def __init__(self):
        self.regexp_firstname = r'^[A-Za-z]{2,25}$'
        self.regexp_lastname = r'^[A-Za-z]{2,25}$'
        self.regexp_username = r'^[A-Za-z0-9]{5,25}$'
        self.regexp_password = r'^[A-Za-z0-9]{8,}$'
        self.regexp_feedback_title = r'^[\w\d\s,\.]{5,255}$'
        self.regexp_feedback_text = r'^[\w\d\s,\.]{5,255}$'
    def validate_firstname(self, firstname):
        try:
            if match(self.regexp_firstname, firstname) is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Firstname should meet with expression: {}".format(self.regexp_firstname)
                    }
                }
            return {"state": True, "firstname": firstname}
        except:
            return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Unknown Error with Firstname"
                    }
                }
    def validate_lastname(self, lastname):
        try:
            if match(self.regexp_lastname, lastname) is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Lastname should meet with expression: {}".format(self.regexp_lastname)
                    }
                }
            return {"state": True, "lastname": lastname}
        except:
            return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Unknown Error with Lastname"
                    }
                }
    def validate_username(self, username):
        try:
            if match(self.regexp_username, username) is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Username should meet with expression: {}".format(self.regexp_username)
                    }
                }
            return {"state": True, "username": username}
        except:
            return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Unknown Error with Username"
                    }
                }
    def validate_password(self, password):
        try:
            if match(self.regexp_password, password) is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Password should meet with expression: {}".format(self.regexp_password)
                    }
                }
            return {"state": True, "password": password}
        except:
            return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Unknown Error with Password"
                    }
                }
    def validate_password_x2(self, password1, password2):
        try:
            if password1 != password2:
                return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Password and Confirmation Password should be same"
                    }
                }
            return {"state": True}
        except:
            return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Unknown Error with Password/confirmation Password"
                    }
                }
    def validate_email(self, email):
        try:
            validate_email(email)
            return {"state": True, "email": email}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Email Address is invalid"
                }
            }
    def validate_limit(self, limit):
        try:
            if isinstance(limit, int) and limit >= 0:
                return {"state": True, "limit": limit}
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Liimit value is invalid"
                }
            }
        except:
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Email Address is invalid"
                }
            }
    def validate_timeframe(self, timeframe):
        try:
            if isinstance(timeframe, int) and 0 <= timeframe <= 525600:
                return {"state": True, "timeframe": timeframe}
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Timeframe value is invalid"
                }
            }
        except:
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Timeframe is invalid"
                }
            }
    def validate_mode(self, mode):
        try:
            if mode in ("table", "chart"):
                return {"state": True, "mode": mode}
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Mode value is invalid"
                }
            }
        except:
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Mode is invalid"
                }
            }
    def validate_chart(self, chart):
        try:
            if chart in ("line", "bar", "pie"):
                return {"state": True, "chart": chart}
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Chart type is invalid"
                }
            }
        except:
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Mode is invalid"
                }
            }
    def validate_report(self, report):
        try:
            report = [axis.strip() for axis in report.split("_") if len(axis.strip())]
            if len(report) == 2:
                return {"state": True, "report": report}
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Selected report ID is invalid"
                }
            }
        except:
            return {
                "state": False,
                "info": {
                    "title": "Validation Error",
                    "text": "Mode is invalid"
                }
            }
    def validate_feedback_title(self, title):
        try:
            if match(self.regexp_feedback_title, title) is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Feedback title should meet with expression: {}".format(self.regexp_feedback_title)
                    }
                }
            return {"state": True, "title": title}
        except:
            return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Unknown Error with feedback title"
                    }
                }
    def validate_feedback_text(self, text):
        try:
            if match(self.regexp_feedback_text, text) is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Feedback text should meet with expression: {}".format(self.regexp_feedback_text)
                    }
                }
            return {"state": True, "text": text}
        except:
            return {
                    "state": False,
                    "info": {
                        "title": "Validation Error",
                        "text": "Unknown Error with feedback text"
                    }
                }