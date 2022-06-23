from unittest import result
from pymysql import connect
from pymysql import cursors
from datetime import timedelta
from datetime import datetime
from os import urandom

class Database:
    def __init__(self, configs):
        self.DB_NAME = configs["DB_NAME"]
        self.DB_HOST = configs["DB_HOST"]
        self.DB_PORT = configs["DB_PORT"]
        self.DB_USER = configs["DB_USER"]
        self.DB_CODE = configs["DB_CODE"]
    def connect(self):
        try:
            self.conn = connect(database=self.DB_NAME,
                                host=self.DB_HOST,
                                port=self.DB_PORT,
                                user=self.DB_USER,
                                password=self.DB_CODE)
            self.curs = self.conn.cursor(cursors.DictCursor)
        except:
            self.conn = None
            self.curs = None
    def disconnect(self):
        try:
            if self.conn or self.curs:
                self.curs.close()
                self.conn.close()
        except:
            pass
    def sessions_init(self, username, password):
        try:
            print(username, password)
            sql = "SELECT * FROM `accounts` WHERE `username`=%s AND `password`=%s AND `state`=%s"
            self.curs.execute(sql, (username, password, 1))
            accounts = self.curs.fetchall()
            if not len(accounts):
                return {
                    "state": False,
                    "info": {
                        "title": "Access Restriction",
                        "text": "Active account {} has not been found".format(username)
                    }
                }
            
            sql = "SELECT * FROM `sessions` WHERE `username`=%s"
            self.curs.execute(sql, [(username)])
            s_session = self.curs.fetchone()
            #print(s_session)
            if s_session:
                token = s_session["token"]
                #print(token)
                s_session = self.sessions_validate(token)
                if s_session["state"]:
                    return {"state": True, "token": token}
            sql = "SELECT * FROM `constants`"
            self.curs.execute(sql)
            constants = self.curs.fetchone()
            if constants is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Constants have not been found in database"
                    }
                }
            #print(constants)
            token = urandom(constants["token_size"]).hex()
            expire = datetime.now() + timedelta(seconds=constants["deadline_session"])
            #print(token, expire)
            sql = "INSERT INTO `sessions` (`username`,`token`,`expire`) VALUES (%s,%s,%s)"
            self.curs.execute(sql, (username, token, expire.strftime('%Y-%m-%d %H:%M:%S')))
            self.conn.commit()
            return {"state": True, "token": token}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Unknown Error with New Session Initialization"
                }
            }
    def sessions_complete(self, token):
        try:
            sql = "DELETE FROM `sessions` WHERE `token`=%s"
            self.curs.execute(sql, [(token)])
            self.conn.commit()
            return {"state": True}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Unknown Error with Session Token"
                }
            }
    def sessions_validate(self, token):
        try:
            sql = "SELECT * FROM `sessions` WHERE `token`=%s"
            self.curs.execute(sql, [(token)])
            s_session = self.curs.fetchone()
            if s_session is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Access Restriction",
                        "text": "Authorize to access that page"
                    }
                }
            if datetime.now() >= s_session["expire"]:
                self.sessions_complete(token)
                return {
                    "state": False,
                    "info": {
                        "title": "Access Restriction",
                        "text": "Token has not been expired and removed from database"
                    }
                }
            return {"state": True}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Unknown Error with Session Token"
                }
            }
    def accounts_get(self, username=None, email=None, token=None):
        try:
            account = None
            if username:
                sql = "SELECT * FROM `accounts` WHERE `username`=%s"
                self.curs.execute(sql, [(username)])
                account = self.curs.fetchone()
            elif email:
                sql = "SELECT * FROM `accounts` WHERE `email`=%s"
                self.curs.execute(sql, [(username)])
                account = self.curs.fetchone()
            elif token:
                sql = "SELECT * FROM `sessions` WHERE `token`=%s"
                self.curs.execute(sql, [(token)])
                s_session = self.curs.fetchone()
                if s_session is None:
                    pass
                sql = "SELECT * FROM `accounts` WHERE `username`=%s"
                self.curs.execute(sql, [(s_session["username"])])
                account = self.curs.fetchone()
            else:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Give any data to search an account"
                    }
                }
            if account is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Account has not been found"
                    }
                }
            account.pop("password")
            return {"state": True, "account": account}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Unknown Error with Account Identification"
                }
            }
    def accounts_add(self, username, password, email, firstname, lastname):
        try:
            sql = "SELECT * FROM `accounts` WHERE `username`=%s OR `email`=%s"
            self.curs.execute(sql, (username, email))
            accounts = self.curs.fetchall()
            if len(accounts):
                return {
                    "state": False,
                    "info": {
                        "title": "Sign Up Restriction",
                        "text": "Give username/email has been registered"
                    }
                }
            sql = "SELECT * FROM `constants`"
            self.curs.execute(sql)
            constants = self.curs.fetchone()
            if constants is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Constants have not been found in database"
                    }
                }
            token = urandom(constants["token_size"]).hex()
            expire = datetime.now() + timedelta(seconds=constants["deadline_activation"])
            sql = "SELECT * FROM `accounts` WHERE `role`='admin'"
            self.curs.execute(sql)
            admins = self.curs.fetchall()
            sql = "INSERT INTO `accounts` (`username`,`password`,`email`,`firstname`,`lastname`,`role`) VALUES (%s,%s,%s,%s,%s,%s)"
            if not len(admins):
                self.curs.execute(sql, (username, password, email, firstname, lastname, "admin"))
            else:
                self.curs.execute(sql, (username, password, email, firstname, lastname, "user"))
            sql = "INSERT INTO `requests` (`username`,`token`,`expire`) VALUES (%s,%s,%s)"
            self.curs.execute(sql, (username, token, expire.strftime('%Y-%m-%d %H:%M:%S')))
            self.conn.commit()
            return {"state": True, "token": token}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Sign Up Rejection",
                    "text": "Account has not been created and/or confirmation request has not been sent"
                }
            }
    def accounts_enable(self, token):
        try:
            sql = "SELECT * FROM `requests` WHERE `token`=%s"
            self.curs.execute(sql, [(token)])
            request = self.curs.fetchone()
            if request is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Activation Error",
                        "text": "Given token has already been activated"
                    }
                }
            if datetime.now() >= request["expire"]:
                return {
                    "state": False,
                    "info": {
                        "title": "Activation Error",
                        "text": "Given token has already been expired. User should reset password"
                    }
                }
            sql = "SELECT * FROM `accounts` WHERE `username`=%s"
            self.curs.execute(sql, [(request["username"])])
            account = self.curs.fetchone()
            if account is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Activation Error",
                        "text": "No any account is related to given token"
                    }
                }
            sql = "UPDATE `accounts` SET `state`=%s WHERE `username`=%s"
            self.curs.execute(sql, (1, request["username"]))
            self.conn.commit()
            sql = "SELECT * FROM `accounts` WHERE `username`=%s AND `state`=%s"
            self.curs.execute(sql, (request["username"], 1))
            account = self.curs.fetchone()
            if account is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Activation Error",
                        "text": "Account state has not been updated"
                    }
                }
            sql = "DELETE FROM `requests` WHERE `token`=%s"
            self.curs.execute(sql, [(token)])
            self.conn.commit()
            return {
                "state": True,
                "info": {
                    "title": "Completed Activation",
                    "text": "Account has been activated"
                }
            }
        except:
            return {
                "state": False,
                "info": {
                    "title": "Activation Error",
                    "text": "Unknown Error during the account activation"
                }
            }
    def constants_get(self):
        try:
            sql = "SELECT * FROM `constants`"
            self.curs.execute(sql)
            constants = self.curs.fetchone()
            constants.pop("comments")
            return {"state": True, "constants": constants}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Constants have not been found in database"
                }
            }
    def application_get(self):
        try:
            sql = "SELECT * FROM `application`"
            self.curs.execute(sql)
            application = self.curs.fetchone()
            return {"state": True, "application": application}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Application data has not been found in database"
                }
            }
    def requests_password_add(self, email):
        try:
            #print(email)
            sql = "SELECT * FROM `accounts` WHERE `email`=%s"
            self.curs.execute(sql, [(email)])
            account = self.curs.fetchone()
            if account is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Given email address \"{}\" has not been found in database!".format(email)
                    }
                }
            #print(account)
            sql = "SELECT * FROM `constants`"
            self.curs.execute(sql)
            constants = self.curs.fetchone()
            if constants is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Constants have not been found in database"
                    }
                }
            #print(constants)
            token = urandom(constants["token_size"]).hex()
            expire = datetime.now() + timedelta(seconds=constants["deadline_reset"])
            #print(token, expire)
            sql = "INSERT INTO `requests` (`username`,`token`,`expire`) VALUES (%s,%s,%s)"
            self.curs.execute(sql, (account["username"], token, expire.strftime('%Y-%m-%d %H:%M:%S')))
            self.conn.commit()
            return {"state": True, "firstname": account["firstname"], "token": token}
        except:
            return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Request data has not been given from database (for email address {})".format(email)
                    }
                }
    def requests_password_delete(self, token, new_password):
        try:
            sql = "SELECT * FROM `requests` WHERE `token`=%s"
            self.curs.execute(sql, [(token)])
            r_request = self.curs.fetchone()
            if r_request is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Reset token has not been found and request has been rejected"
                    }
                }
            if datetime.now() >= r_request["expire"]:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Reset token has been expired and request has been rejected"
                    }
                }
            sql = "SELECT * FROM `accounts` WHERE `username`=%s"
            self.curs.execute(sql, [(r_request["username"])])
            account = self.curs.fetchone()
            if account is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Account related to given token has not been found (for account <{}>)".format(r_request["username"])
                    }
                }
            sql = "UPDATE `accounts` SET `password`=%s WHERE `username`=%s"
            self.curs.execute(sql, (new_password, r_request["username"]))
            self.conn.commit()
            sql = "SELECT * FROM `accounts` WHERE `username`=%s AND `password`=%s"
            self.curs.execute(sql, (r_request["username"], new_password))
            account = self.curs.fetchone()
            if account is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "New password has not been saved for account <{}>".format(r_request["username"])
                    }
                }
            sql = "DELETE FROM `requests` WHERE `token`=%s"
            self.curs.execute(sql, [(token)])
            self.conn.commit()
            return {
                "state": True,
                "info": {
                    "title": "Successfully Updated",
                    "text": "New password has been saved (for account <{}>)".format(r_request["username"])
                }
            }
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Reset password request has not been completed (for account <{}>)".format(r_request["username"])
                }
            }
    def notifications_get(self, all=False):
        try:
            if not all:
                sql = "SELECT * FROM `notifications` WHERE `expire`>%s"
                self.curs.execute(sql, [(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))])
            else:
                sql = "SELECT * FROM `notifications`"
                self.curs.execute(sql)
            notifications = self.curs.fetchall()
            #print(notifications)
            if not len(notifications):
                return {"state": True, "notifications": notifications}
            return {"state": True, "notifications": notifications, "fields": list(notifications[0].keys())}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Notifications have not been found in database"
                }
            }
    def notifications_update(self):
        pass
    def table_get(self, admin_mode = False):
        try:
            sql = "SELECT * FROM `sorts`"
            self.curs.execute(sql)
            sort_modes = self.curs.fetchall()
            sort_modes = { mode["id"]:mode["variable"] for mode in sort_modes }
            #print(sort_modes)
            sql = "SELECT * FROM `constants`"
            self.curs.execute(sql)
            constants = self.curs.fetchone()
            if constants is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Constants have not been found in database"
                    },
                    "placeholder": "No items to display"
                }
            #print(constants)
            sql = "SELECT * FROM `sources` WHERE `state`='1'"
            self.curs.execute(sql)
            sources = self.curs.fetchall()
            if not len(sources):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "No sources to display data"
                    },
                    "placeholder": "No items to display"
                }
            tables = [source["table"] for source in sources]
            #print(tables)
            sql = "SELECT * FROM `view_table` WHERE `options`=%s"
            self.curs.execute(sql, [("order")])
            order = self.curs.fetchone()
            order.pop("options")
            #order.pop("comments")
            order = { int(order[i]):i for i in order }
            order = [order[i] for i in sorted(order.keys())]
            #print(order)
            sql = "SELECT * FROM `view_table` WHERE `options`=%s"
            self.curs.execute(sql, [("visibility")])
            columns = self.curs.fetchone()
            columns.pop("options")
            #columns.pop("comments")
            columns = [column for column in order if columns[column]=="1"]
            #print(columns)
            sql = "SELECT * FROM `view_table` WHERE `options`=%s"
            self.curs.execute(sql, [("sort")])
            sorts = self.curs.fetchone()
            sorts = [sort_modes[int(sorts[column])] for column in columns]
            #print(sorts)
            #print(admin_mode)
            if admin_mode:
                sql = "SELECT {} FROM {} {} {}".format(
                    ",".join(["`{}`".format(column) for column in columns]),
                    ",".join(["`{}`".format(table) for table in tables]),
                    "ORDER BY {}".format(",".join(["`{}` {}".format(columns[i], sorts[i]) for i in range(len(columns))])),
                    "LIMIT {}".format(constants["limit"]) if constants["limit"] else "")
            else:
                sql = "SELECT {} FROM {} WHERE {} {} {}".format(
                    ",".join(["`{}`".format(column) for column in columns]),
                    ",".join(["`{}`".format(table) for table in tables]),
                    "`archived`='0000-00-00 00:00:00'",
                    "ORDER BY {}".format(",".join(["`{}` {}".format(columns[i], sorts[i]) for i in range(len(columns))])),
                    "LIMIT {}".format(constants["limit"]) if constants["limit"] else "")
                sql = "SELECT {} FROM {} WHERE {} {} {}".format(
                    ",".join(["`{}`".format(column) for column in columns]),
                    ",".join(["`{}`".format(table) for table in tables]),
                    "`archived`='0000-00-00 00:00:00'",
                    "ORDER BY {}".format(",".join(["`{}` {}".format(columns[i], sorts[i]) for i in range(len(columns))])),
                    "LIMIT {}".format(constants["limit"]) if constants["limit"] else "")
            print(sql)
            self.curs.execute(sql)
            rows = self.curs.fetchall()
            #print(len(rows))
            if not len(rows):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Selected tables are empty"
                    },
                    "placeholder": "No items to display"
                }
            return {"state": True, "limit": constants["limit"], "rows": rows, "columns": columns}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Items have not been loaded from database"
                },
                "placeholder": "No items to display"
            }
    def table_update(self):
        pass
    def chart_get(self, admin_mode = False):
        dataset = {
            "caption": "",
            "layouts": {
                "quantity": 0,
                "data": {},
                "x-axis": {
                    "title": "",
                    "min": 0,
                    "max": 0
                },
                "y-axis": {
                    "title": "",
                    "min": 0,
                    "max": 0
                }
            },
            "type": "",
            "custom":None
        }
        # timeframe/limit;
        sql = "SELECT `timeframe`,`limit` FROM `constants`"
        self.curs.execute(sql)
        constants = self.curs.fetchone()
        dataset["limit"] = constants["limit"]
        # chart settings;
        sql = "SELECT * FROM `view_chart`"
        self.curs.execute(sql)
        view_chart = self.curs.fetchone()
        # report settings;
        sql = "SELECT * FROM `reports` WHERE `id`=%s"
        self.curs.execute(sql, [(view_chart["report_id"])])
        report = self.curs.fetchone()
        # caption;
        dataset["caption"] = report["title"]
        if not view_chart["report_id"]:
            dataset["caption"] = "{} ({} x {})".format(report["title"],view_chart["x_axis"].capitalize(),view_chart["y_axis"].capitalize())
            dataset["custom"] = True
        # chart form;
        sql = "SELECT `variable` FROM `charts` WHERE `id`=%s"
        self.curs.execute(sql, [(view_chart["chart_id"])])
        chart = self.curs.fetchone()
        dataset["type"] = chart["variable"]
        # layouts;
        dataset["layouts"]["quantity"] = sum([report["min"], report["max"], report["avg"]])
        # list of tables;
        sql = "SELECT `table` FROM `sources` WHERE `state`='1'"
        self.curs.execute(sql)
        sources = self.curs.fetchall()
        tables = [source["table"] for source in sources]
        if not len(tables):
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "No data to display has been found in database"
                }
            }
        print(report)
        # X/Y;
        if admin_mode:
            sql = "SELECT `{}`,`{}` FROM {} {}".format(
                report["x_axis"], report["y_axis"],
                ",".join(["`{}`".format(table) for table in tables]),
                "LIMIT {}".format(constants["limit"]) if constants["limit"] else "")
        else:
            sql = "SELECT `{}`,`{}` FROM {} WHERE {} {}".format(
                report["x_axis"], report["y_axis"],
                ",".join(["`{}`".format(table) for table in tables]),
                "`archived`='0000-00-00 00:00:00'",
                "LIMIT {}".format(constants["limit"]) if constants["limit"] else "")
        self.curs.execute(sql)
        rows = self.curs.fetchall()
        if not len(rows):
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "No data to display has been found in database"
                }
            }
        #print(rows, report["x_axis"], report["y_axis"])
        dataset["layouts"]["data"]["x"] = sorted(set([str(row[report["x_axis"]]) for row in rows]))
        dataset["layouts"]["data"]["y"] = {x:[] for x in dataset["layouts"]["data"]["x"]}
        for row in rows:
            x = str(row[report["x_axis"]])
            y = row[report["y_axis"]]
            if isinstance(y, datetime):
                dataset["layouts"]["data"]["y"][x].append(y.strftime("%Y-%m-%d %H:%M:%S"))
            elif isinstance(y, str) and y.isnumeric():
                dataset["layouts"]["data"]["y"][x].append(int(y))
            else:
                dataset["layouts"]["data"]["y"][x].append(y)
        if dataset["layouts"]["quantity"] > 1:
            dataset["layouts"]["data"]["y"] = {
                "min": [min(dataset["layouts"]["data"]["y"][x]) for x in dataset["layouts"]["data"]["x"]],
                "max": [max(dataset["layouts"]["data"]["y"][x]) for x in dataset["layouts"]["data"]["x"]],
                "avg": [sum(dataset["layouts"]["data"]["y"][x])/len(dataset["layouts"]["data"]["y"][x]) for x in dataset["layouts"]["data"]["x"]]}
            
        else:
            dataset["layouts"]["data"]["y"] = [len(dataset["layouts"]["data"]["y"][x]) for x in dataset["layouts"]["data"]["x"]]
        # axis MIN/MAX;
        dataset["layouts"]["x-axis"]["title"] = report["x_axis"].capitalize()
        dataset["layouts"]["y-axis"]["title"] = report["y_axis"].capitalize()
        dataset["layouts"]["x-axis"]["min"],dataset["layouts"]["x-axis"]["max"] = dataset["layouts"]["data"]["x"][0],dataset["layouts"]["data"]["x"][-1]
        if dataset["layouts"]["quantity"] > 1:
            y_min = min([min(dataset["layouts"]["data"]["y"]["min"]), min(dataset["layouts"]["data"]["y"]["max"]), min(dataset["layouts"]["data"]["y"]["avg"])])
            y_max = max([max(dataset["layouts"]["data"]["y"]["min"]), max(dataset["layouts"]["data"]["y"]["max"]), max(dataset["layouts"]["data"]["y"]["avg"])])
            dataset["layouts"]["y-axis"]["min"] = y_min if dataset["layouts"]["y-axis"]["min"] > y_min else dataset["layouts"]["y-axis"]["min"]
            dataset["layouts"]["y-axis"]["max"] = y_min if dataset["layouts"]["y-axis"]["max"] > y_min else dataset["layouts"]["y-axis"]["max"]
            dataset["layouts"]["y-axis"]["colors"] = {
                "min": view_chart["source_color_1"],
                "max": view_chart["source_color_2"],
                "avg": view_chart["source_color_3"]
            }
        else:
            y_min = min(dataset["layouts"]["data"]["y"])
            y_max = max(dataset["layouts"]["data"]["y"])
            dataset["layouts"]["y-axis"]["min"] = y_min if dataset["layouts"]["y-axis"]["min"] > y_min else dataset["layouts"]["y-axis"]["min"]
            dataset["layouts"]["y-axis"]["max"] = y_max if y_max > dataset["layouts"]["y-axis"]["max"] else dataset["layouts"]["y-axis"]["max"]
            dataset["layouts"]["y-axis"]["color"] = view_chart["source_color_1"]
        print(dataset)
        sql = "SELECT `x_axis` FROM `reports`"
        self.curs.execute(sql)
        x_axis = ["updated","archived","company","location","place","product","quality","price","deviation"]
        y_axis = ["updated","archived","company","location","place","product","quality","price","deviation"]
        print(dataset["custom"])
        return {"state": True, "dataset": dataset, "custom":{"x_axis": x_axis, "y_axis": y_axis, "x":view_chart["x_axis"], "y":view_chart["y_axis"]}}
    def limits_get(self):
        try:
            sql = "SELECT * FROM `limits`"
            self.curs.execute(sql)
            limits = self.curs.fetchall()
            if not len(limits):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of Limits is empty"
                    }
                }
            return {"state": True, "limits": limits}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Limits have not been found in database"
                }
            }
    def limits_update(self, limit):
        try:
            sql = "UPDATE `constants` SET `limit`=%s"
            self.curs.execute(sql, [(limit)])
            self.conn.commit()
            return {"state": True}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Current Limit has not been updated in database"
                }
            }
    def timeframes_get(self):
        try:
            sql = "SELECT * FROM `timeframes`"
            self.curs.execute(sql)
            timeframes = self.curs.fetchall()
            if not len(timeframes):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of timeframes is empty"
                    }
                }
            return {"state": True, "timeframes": timeframes}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Timeframes have not been found in database"
                }
            }
    def timeframes_update(self, timeframe):
        try:
            sql = "UPDATE `constants` SET `timeframe`=%s"
            self.curs.execute(sql, [(timeframe)])
            self.conn.commit()
            return {"state": True}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Current timeframe has not been updated in database"
                }
            }
    def modes_get(self):
        try:
            sql = "SELECT * FROM `modes`"
            self.curs.execute(sql)
            modes = self.curs.fetchall()
            if not len(modes):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of modes is empty"
                    }
                }
            return {"state": True, "modes": modes}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Modes have not been found in database"
                }
            } 
    def modes_update(self, mode):
        try:
            sql = "UPDATE `constants` SET `mode`=%s"
            self.curs.execute(sql, [(mode)])
            self.conn.commit()
            return {"state": True}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Current mode has not been updated in database"
                }
            }
    def charts_get(self):
        try:
            sql = "SELECT * FROM `charts`"
            self.curs.execute(sql)
            charts = self.curs.fetchall()
            if not len(charts):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of chart types is empty"
                    }
                }
            return {"state": True, "charts": charts}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Chart types have not been found in database"
                }
            }
    def charts_update(self, chart):
        try:
            sql = "SELECT * FROM `charts` WHERE `variable`=%s"
            self.curs.execute(sql, [(chart)])
            chart_id = self.curs.fetchone()
            if chart_id is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Selected chart type has not been found in database"
                    }
                }
            sql = "UPDATE `view_chart` SET `chart_id`=%s"
            self.curs.execute(sql, [(chart_id["id"])])
            self.conn.commit()
            return {"state": True}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Current chart type has not been updated in database"
                }
            }
    def reports_get(self):
        try:
            sql = "SELECT * FROM `reports`"
            self.curs.execute(sql)
            reports = self.curs.fetchall()
            if not len(reports):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of reports is empty"
                    }
                }
            return {"state": True, "reports": reports}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Reports have not been found in database"
                }
            }
    def reports_update(self, report, custom=False):
        try:
            sql = "SELECT * FROM `reports` WHERE `x_axis`=%s AND `y_axis`=%s"
            self.curs.execute(sql, (report[0], report[1]))
            report = self.curs.fetchall()
            if not len(report):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "Selected report has not been found in database"
                    }
                }
            sql = "UPDATE `view_chart` SET `report_id`=%s"
            if custom:
                self.curs.execute(sql, [(report[0]["id"])])
            else:
                self.curs.execute(sql, [(report[-1]["id"])])
            self.conn.commit()
            return {"state": True}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Current chart\'s report has not been updated in database"
                }
            }
    def sessions_get(self):
        try:
            sql = "SELECT * FROM `sessions`"
            self.curs.execute(sql)
            sessions = self.curs.fetchall()
            if not len(sessions):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of sessions is empty"
                    }
                }
            return {"state": True, "sessions": sessions}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Sessions have not been found in database"
                }
            }
    def sources_get(self):
        try:
            sql = "SELECT * FROM `sessions`"
            self.curs.execute(sql)
            sessions = self.curs.fetchall()
            if not len(sessions):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of sessions is empty"
                    }
                }
            return {"state": True, "sessions": sessions}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Sessions have not been found in database"
                }
            }
    def spiders_get(self):
        try:
            sql = "SELECT * FROM `spiders`"
            self.curs.execute(sql)
            spiders = self.curs.fetchall()
            if not len(spiders):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of spiders is empty"
                    }
                }
            return {"state": True, "spiders": spiders}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Spiders have not been found"
                }
            }
    def view_tables_get(self):
        try:
            sql = "SELECT * FROM `view_table`"
            self.curs.execute(sql)
            view_table = self.curs.fetchall()
            if not len(view_table):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of table settings is empty"
                    }
                }
            return {"state": True, "view_table": view_table}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Table settings have not been found in database"
                }
            }
    def view_charts_get(self):
        try:
            sql = "SELECT * FROM `view_chart`"
            self.curs.execute(sql)
            view_chart = self.curs.fetchone()
            if view_chart is None:
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of chart settings is empty"
                    }
                }
            return {"state": True, "view_chart": view_chart}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Chart settings have not been found in database"
                }
            }
    def requests_get(self):
        try:
            sql = "SELECT * FROM `requests`"
            self.curs.execute(sql)
            requests = self.curs.fetchall()
            if not len(requests):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of requests is empty"
                    }
                }
            return {"state": True, "requests": requests}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Requests have not been found in database"
                }
            }
    def axis_update(self, axis, title):
            print(axis,title)
            if axis == "x":
                sql = "UPDATE `view_chart` SET `x_axis`=%s"
                self.curs.execute(sql, [(title)])
                sql = "UPDATE `reports` SET `x_axis`=%s WHERE `id`=%s"
                self.curs.execute(sql, (title,0))
            else:
                sql = "UPDATE `view_chart` SET `y_axis`=%s"
                self.curs.execute(sql, [(title)])
                sql = "UPDATE `reports` SET `y_axis`=%s WHERE `id`=%s"
                self.curs.execute(sql, (title,0))
            self.conn.commit()
            sql = "UPDATE `view_chart` SET `report_id`=%s"
            self.curs.execute(sql, [(0)])
            self.conn.commit()
            return {"state": True}
        
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Axis has not been found in database"
                }
            }
    def settings_get(self, table):
        
            support={}
            if table == "application":
                sql = "SELECT * FROM `application`"
                self.curs.execute(sql)
                settings = self.curs.fetchone()
                if settings is None:
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of application data is empty"
                        }
                    }
            elif table == "notifications":
                pass
            elif table == "sessions":
                sql = "SELECT * FROM `sessions`"
                self.curs.execute(sql)
                settings = self.curs.fetchall()
                if not len(settings):
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of sessions is empty"
                        }
                    }
                for i in range(len(settings)):
                    settings[i].pop("comments")
            elif table == "accounts":
                sql = "SELECT * FROM `accounts`"
                self.curs.execute(sql)
                settings = self.curs.fetchall()
                if not len(settings):
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of accounts is empty"
                        }
                    }
                for i in range(len(settings)):
                    settings[i].pop("password")
                print(settings)
                sql = "SELECT * FROM `roles`"
                self.curs.execute(sql)
                support["roles"] = self.curs.fetchall()
            elif table == "sources":
                sql = "SELECT * FROM `sources`"
                self.curs.execute(sql)
                settings = self.curs.fetchall()
                if not len(settings):
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of sources is empty"
                        }
                    }
                for i in range(len(settings)):
                    settings[i].pop("comments")
            elif table == "view_table":
                sql = "SELECT * FROM `view_table`"
                self.curs.execute(sql)
                settings = self.curs.fetchall()
                if not len(settings):
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of view table is empty"
                        }
                    }
                support["order"] = list(range(1, len(settings[0].keys())))
                settings = {
                    settings[0]["options"]:{i:settings[0][i] for i in settings[0] if i != "options"},
                    settings[1]["options"]:{i:settings[1][i] for i in settings[1] if i != "options"},
                    settings[2]["options"]:{i:settings[2][i] for i in settings[2] if i != "options"}
                }
                sql = "SELECT * FROM `visibility`"
                self.curs.execute(sql)
                support["visibility"] = self.curs.fetchall()
                if not len(support["visibility"]):
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of view table visibility is empty"
                        }
                    }
                sql = "SELECT * FROM `sorts`"
                self.curs.execute(sql)
                support["sort"] = self.curs.fetchall()
                if not len(support["sort"]):
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of view table visibility sorts is empty"
                        }
                    }
            elif table == "view_chart":
                sql = "SELECT * FROM `view_chart`"
                self.curs.execute(sql)
                settings = self.curs.fetchone()
                if settings is None:
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of view chart data is empty"
                        }
                    }
                sql = "SELECT * FROM `reports`"
                self.curs.execute(sql)
                support["reports"] = self.curs.fetchall()
                sql = "SELECT * FROM `charts`"
                self.curs.execute(sql)
                support["charts"] = self.curs.fetchall()
                sql = "SELECT `x_axis` FROM `reports`"
                self.curs.execute(sql)
                support["x_axis"] = ["updated","archived","company","location","place","product","quality","price","deviation"]
                support["y_axis"] = ["updated","archived","company","location","place","product","quality","price","deviation"]
            elif table == "requests":
                pass
            elif table == "reports":
                pass
            elif table == "feedbacks":
                sql = "SELECT * FROM `feedbacks`"
                self.curs.execute(sql)
                settings = self.curs.fetchall()
                if not len(settings):
                    return {
                        "state": False,
                        "info": {
                            "title": "Database Error",
                            "text": "List of feedbacks is empty"
                        }
                    }
                for i in range(len(settings)):
                    if isinstance(settings[i]["date"], datetime):
                        settings[i]["date"] = settings[i]["date"].strftime("%Y-%m-%d %H:%M:%S")
            sql = "SHOW COLUMNS FROM `{}`".format(table)
            self.curs.execute(sql)
            fields = self.curs.fetchall()
            print(fields)
            return {"state": True, table: settings, "fields": fields, "support":support}
        
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Table {} has not been found in database".format(table.capitalize())
                }
            }
    def settings_update(self, table=None, field=None, value=None, primary=None, key=None):
        
            if table == "application":
                sql = "UPDATE `{}` SET `{}`=%s".format(table, field)
                self.curs.execute(sql, [(value)])
            elif table == "notifications":
                pass
            elif table == "sessions":
                if primary == "-" and key == "-":
                    sql = "DELETE FROM `{}` WHERE `{}`=%s".format(table, primary)
                    self.curs.execute(sql, [(key)])
                else:
                    sql = "DELETE FROM `{}` WHERE 1".format(table)
                    self.curs.execute(sql)
            elif table == "accounts":
                sql = "UPDATE `{}` SET `{}`=%s WHERE `{}`=%s".format(table, field, primary)
                self.curs.execute(sql, (value, key))
            elif table == "sources":
                sql = "UPDATE `{}` SET `{}`=%s WHERE `{}`=%s".format(table, field, primary)
                self.curs.execute(sql, (value, key))
            elif table == "spiders":
                pass
            elif table == "view_table":
                if key == "order":
                    sql = "SELECT * FROM `{}` WHERE `{}`=%s".format(table, primary)
                    self.curs.execute(sql, [(key)])
                    result = self.curs.fetchone()
                    old_field = field
                    old_index = result[field]
                    result = {i:result[i] for i in result if result[i] == value}
                    new_field = list(result.items())[0][0]
                    new_index = list(result.items())[0][1]
                    sql = "UPDATE `{}` SET `{}`=%s WHERE `{}`=%s".format(table, old_field, primary)
                    self.curs.execute(sql, (new_index, key))
                    sql = "UPDATE `{}` SET `{}`=%s WHERE `{}`=%s".format(table, new_field, primary)
                    self.curs.execute(sql, (old_index, key)) 
                else:
                    sql = "UPDATE `{}` SET `{}`=%s WHERE `{}`=%s".format(table, field, primary)
                    self.curs.execute(sql, (value, key))
            elif table == "view_chart":
                if field == "x_axis":
                    sql = "UPDATE `{}` SET `{}`=%s".format(table, field)
                    self.curs.execute(sql, [(value)])
                    sql = "UPDATE `reports` SET `x_axis`=%s WHERE `id`=%s"
                    self.curs.execute(sql, (value, 0))
                if field == "y_axis":
                    sql = "UPDATE `{}` SET `{}`=%s".format(table, field)
                    self.curs.execute(sql, [(value)])
                    sql = "UPDATE `reports` SET `y_axis`=%s WHERE `id`=%s"
                    self.curs.execute(sql, (value, 0))
                if field == "report_id":
                    sql = "SELECT * FROM `reports` WHERE `id`=%s"
                    self.curs.execute(sql, [(value)])
                    axis = self.curs.fetchone()
                    sql = "UPDATE `{}` SET `{}`=%s, `x_axis`=%s, `y_axis`=%s".format(table, field)
                    self.curs.execute(sql, (value, axis["x_axis"], axis["y_axis"]))
                else:
                    sql = "UPDATE `{}` SET `{}`=%s".format(table, field)
                    self.curs.execute(sql, [(value)])
            elif table == "requests":
                pass
            elif table == "reports":
                pass
            elif table == "feedbacks":
                sql = "UPDATE `{}` SET `{}`=%s WHERE `{}`=%s".format(table, field, primary)
                self.curs.execute(sql, (value, key))
            self.conn.commit()
            return {"state": True}
        
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Table {} has not been updated in database".format(table.capitalize())
                }
            }
    def feedbacks_get(self):
        try:
            sql = "SELECT * FROM `feedbacks`"
            self.curs.execute(sql)
            feedbacks = self.curs.fetchall()
            if not len(feedbacks):
                return {
                    "state": False,
                    "info": {
                        "title": "Database Error",
                        "text": "List of feedbacks is empty"
                    }
                }
            for i in range(len(feedbacks)):
                if isinstance(feedbacks[i]["date"], datetime):
                    feedbacks[i]["date"] = feedbacks[i]["date"].strftime("%Y-%m-%d %H:%M:%S")
            sql = "SHOW COLUMNS FROM `feedbacks`"
            self.curs.execute(sql)
            fields = self.curs.fetchall()
            return {"state": True, "feedbacks": feedbacks, "fields": fields}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Feedbacks have not been found in database"
                }
            }
    def feedbacks_add(self, username=None, title=None, text=None):
        try:
            sql = "INSERT INTO `feedbacks` (`username`,`date`,`title`,`text`) VALUES (%s,%s,%s,%s)"
            self.curs.execute(sql,(username,datetime.now().strftime("%Y-%m-%d %H:%M:%S"),title,text))
            self.conn.commit()
            return {"state": True}
        except:
            return {
                "state": False,
                "info": {
                    "title": "Database Error",
                    "text": "Your feedback has not been saved in database"
                }
            }
