from fastapi import FastAPI, Query
import os
app = FastAPI()
@app.get('/implicit')
def implicit(cmd: str):
    os.system(cmd)
@app.get('/explicit')
def explicit(cmd: str = Query(...)):
    os.system(cmd)
