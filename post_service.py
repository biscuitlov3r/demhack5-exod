from flask import *
import gnupg
import core
import sqlite3
import os
from werkzeug.utils import secure_filename
import requests
import random
import hashlib
import json

password = input("password: ")

gpg = gnupg.GPG()
app = Flask(__name__)
UPLOAD_FOLDER = 'downloads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/receive_message_as_post_service', methods = ['POST'])
def receive():
    con = sqlite3.connect("post.db")
    cur = con.cursor()
    if request.method == 'POST':
        message = request.form["message"]
        print("MESSAGE", message)
        provided_id = request.form["provided_id"]
        keyfingerprint = request.form["keyfingerprint"]
        pubkey = request.form["pubkey"]
        recipient = request.form["recipient"]
        nodes = json.loads(request.form["nodes"])
        print("RECIPIENT", recipient)
        try:
            encrypted_filename = request.form["encrypted_filename"]
        except:
            encrypted_filename = None

        # prevent receiving message couple of times, if it has been sent to many nodes
        res = cur.execute("SELECT * FROM messages WHERE provided_id=?", (provided_id,))
        check_for_message = res.fetchone()

        if check_for_message != None:
            print("already")
            return {"status": "error", "message": "message already received"}

        contact = cur.execute("SELECT * FROM users WHERE keyfingerprint=?", (keyfingerprint,)).fetchone()
        print("CONTACT", contact)

        if contact == None:
            import_result = gpg.import_keys(pubkey)
            print(import_result.fingerprints[0], keyfingerprint)

            if import_result.fingerprints[0] != keyfingerprint:
                return {"status": "error", "message": "incorrect keyfingerprint"}

            res = cur.execute("INSERT INTO users(pubkey, keyfingerprint) VALUES(?,?)",
                (pubkey, import_result.fingerprints[0]))
            print(cur.lastrowid)

            contact = cur.execute("SELECT * FROM users WHERE id=?", [(cur.lastrowid)]).fetchone()
            for i in nodes:
                cur.execute("INSERT INTO nodes(userid, onionaddress, isprimary) VALUES(?,?,?)", (contact[0], i["address"], i["isprimary"],))

        myfile = None

        if 'file' in request.files:
            file = request.files['file']

            if not file.filename == '' and file:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
                myfile = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        
        if encrypted_filename != None:
            cur.execute("INSERT INTO messages(userid, text, sender, file, provided_id, filename, recipient) VALUES(?,?,?,?,?,?,?)", 
                (contact[0], message, contact[0], myfile, provided_id, encrypted_filename, recipient))
        else:
            cur.execute("INSERT INTO messages(userid, text, sender, file, provided_id, filename, recipient) VALUES(?,?,?,?,?,?,?)", 
                (contact[0], message, contact[0], myfile, provided_id, None, recipient))
        con.commit()
        con.close()
        return {"status": "success"}

@app.route("/getmymessages", methods = ['POST'])
def getmymessages():
    con = sqlite3.connect("post.db")
    cur = con.cursor()
    if request.method == 'POST':
        key = request.form["key"]
        message = request.form["message"]
        print("KEY", key)
        print("MESSAGE", message) 

        import_result = gpg.import_keys(key)
        print(import_result.fingerprints[0])
        verified = gpg.verify(message)

        messages = cur.execute("SELECT * FROM messages WHERE recipient=?", (import_result.fingerprints[0],)).fetchall()
        print(verified.fingerprint, import_result.fingerprints[0], messages[0][7])

        tosend = []
        if verified.fingerprint == import_result.fingerprints[0]:
            for i in messages:
                print(i)
                user = cur.execute("SELECT * FROM users WHERE id=?", (i[1],)).fetchone()
                nodes = cur.execute("SELECT * FROM nodes WHERE userid=?", (i[1],)).fetchall()
                tosend.append({"message": i, "user": user, "nodes": nodes})
            con.close()
            return {"status": "success", "data": tosend}
        else:
            con.close()
            return {"status": "error", "message": "invalid key"}