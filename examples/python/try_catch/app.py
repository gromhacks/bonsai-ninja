import os

def tainted_through_try():
    try:
        t = os.environ["CMD"]
    except KeyError:
        t = ""
    os.system(t)
