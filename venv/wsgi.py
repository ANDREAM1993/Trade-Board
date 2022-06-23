import sys, os
sys.path.append("{}/venv/app/".format(os.getcwd()))
sys.path.append("{}/venv/lib/python3.8/site-packages".format(os.getcwd()))
from app.main import app
###############
# ENTRY POINT #
###############
if __name__ == "__main__":
    app.run()