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

file = open("config.json", "r")
config = json.loads(file.read())
file.close()
print(config)

@app.route('/receive_message', methods = ['POST'])
def receive():
    con = sqlite3.connect("db.db")
    cur = con.cursor()
    if request.method == 'POST':
        message = request.form["message"]
        print("MESSAGE", message)
        provided_id = request.form["provided_id"]
        keyfingerprint = request.form["keyfingerprint"]
        pubkey = request.form["pubkey"]
        name = request.form["name"]
        status = request.form["status"]
        encrypted_filename = request.form["encrypted_filename"]
        nodes = json.loads(request.form["nodes"])
        print(nodes)

        print(request.form)

        # prevent receiving message couple of times, if it has been sent to many nodes
        res = cur.execute("SELECT * FROM messages WHERE provided_id=?", (provided_id,))
        check_for_message = res.fetchone()

        if check_for_message != None:
            print("already")
            return {"status": "error", "message": "message already received"}

        contact = cur.execute("SELECT * FROM contacts WHERE keyfingerprint=?", (keyfingerprint,)).fetchone()
        print("CONTACT", contact)

        if contact == None:
            import_result = gpg.import_keys(pubkey)
            print(import_result.fingerprints[0], keyfingerprint)

            if import_result.fingerprints[0] != keyfingerprint:
                return {"status": "error", "message": "incorrect keyfingerprint"}

            res = cur.execute("INSERT INTO contacts(pubkey, name, status, keyfingerprint, trusted) VALUES(?,?,?,?,?)",
                (pubkey, name, status, import_result.fingerprints[0], 0))
            print(cur.lastrowid)

            contact = cur.execute("SELECT * FROM contacts WHERE id=?", [(cur.lastrowid)]).fetchone()
            for i in nodes:
                cur.execute("INSERT INTO nodes(userid, onionaddress, isprimary) VALUES(?,?,?)", (contact[0], i["address"], i["isprimary"],))

        decrypted = core.decrypt_string(message, password)
        if decrypted["status"] != "decryption ok":
            return {"status": "error", "message": "failed to decrypt message"}

        print(decrypted)

        decrypted_file = None

        if 'file' in request.files:
            file = request.files['file']

            if not file.filename == '' and file:
                decrypted_filename = core.decrypt_string(encrypted_filename, password)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename["data"]))
                decrypted_file = core.decrypt_file(os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename["data"]), password)["file"]
                print(decrypted_file)
        
        cur.execute("INSERT INTO messages(userid, text, sender, file, provided_id, filename) VALUES(?,?,?,?,?,?)", 
            (contact[0], decrypted["data"], contact[0], decrypted_file, provided_id, os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename["data"].removesuffix(".gpg"))))
        con.commit()
        return {"status": "success"}
        print("ok")

@app.route('/send_message', methods = ['POST'])
def send():
    con = sqlite3.connect("db.db")
    cur = con.cursor()
    recipient = request.form["recipient"]
    message = request.form["message"]

    res = cur.execute("SELECT * FROM contacts WHERE id=?", (recipient,))
    contact = res.fetchone()

    res2 = cur.execute("SELECT * FROM nodes WHERE userid=?", (recipient,))
    nodes = res2.fetchall()

    # contact[4] - keyfingerprint

    encrypted = core.encrypt_string(message, contact[4], password, config["mykey_fingerprint"])
    encrypted_file = None
    encrypted_filename = None

    provided_id = hashlib.sha1( bytes(str(random.randint(0, 999999999999999999999999999999999999999999999999999999999999999999)) + config["mykey_fingerprint"], 'utf-8') ).hexdigest()

    if 'file' in request.files:
        file = request.files['file']

        if not file.filename == '' and file:
            f_name, f_ext = os.path.splitext(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], provided_id+f_ext ) )
            encrypted_filename = core.encrypt_string(provided_id+f_ext +".gpg", contact[4], password, config["mykey_fingerprint"])

            encrypted_file = core.encrypt_file(os.path.join(app.config['UPLOAD_FOLDER'], provided_id+f_ext), 
                contact[4], password, config["mykey_fingerprint"])["filename"]

            os.rename(os.path.join(app.config['UPLOAD_FOLDER'], provided_id+f_ext), os.path.join(app.config['UPLOAD_FOLDER'],(provided_id)))

    # check for primary node(s)

    primary_nodes = []
    
    for node in nodes:
        print("NODE", node)
        if node[3] == 1: # isprimary
            primary_nodes.append(node)
            nodes.remove(node)
    
    public_key = gpg.export_keys(config["mykey_fingerprint"])
    print(provided_id)

    data = {}
    if encrypted_filename != None:
        data = {"message": encrypted["string"], 
            "keyfingerprint": config["mykey_fingerprint"],
            "pubkey": public_key,
            "name": config["name"],
            "status": config["status"],
            "provided_id": provided_id, 
            "recipient": contact[4],
            "encrypted_filename": encrypted_filename["string"],
            "nodes": json.dumps(config["nodes"])
        }
    else:
        data = {"message": encrypted["string"], 
            "keyfingerprint": config["mykey_fingerprint"],
            "pubkey": public_key,
            "name": config["name"],
            "status": config["status"],
            "provided_id": provided_id, 
            "recipient": contact[4],
            "nodes": json.dumps(config["nodes"])
        }
    # primary nodes are onion services, running by account's owner devices
    # other nodes are onion services, running by account's owner trusted contacts
    # that's why we use different methods to send messages here
    # see post_service.py for more information

    for node in primary_nodes:
        try:
            if encrypted_file != None:
                files = {'file': open(encrypted_file,'rb')}
                requests.post(node[2]+"/receive_message", files=files, data=data)
            else:
                requests.post(node[2]+"/receive_message", data=data)

            break
        except Exception as e:
            print(e)
            primary_nodes.remove(node)
            continue
    
    if len(primary_nodes) != 0:
        path = None
        if encrypted_file != None:
            path = os.path.join(app.config['UPLOAD_FOLDER'], provided_id+f_ext)
            os.rename( os.path.join(app.config['UPLOAD_FOLDER'], provided_id), os.path.join(app.config['UPLOAD_FOLDER'], provided_id+f_ext) )
        
        cur.execute("INSERT INTO messages(userid, text, sender, file, provided_id, filename) VALUES(?,?,?,?,?,?)", 
            (contact[0], request.form["message"], "you", encrypted_file, provided_id, path))
        con.commit()
        con.close()
        
        return {"status": "success", "message": "sent to primary nodes", "data": {"nodes_count": len(primary_nodes)}}
    
    # if message has been sent to one of the primary nodes, following code will not be executed:
    data.pop("name")
    data.pop("status")
    for node in nodes: 
        try:
            if encrypted_file != None:
                files = {'file': open(encrypted_file,'rb')}
                requests.post(node[2]+"/receive_message_as_post_service", files=files, data=data)
            else:
                requests.post(node[2]+"/receive_message_as_post_service", data=data)
        except Exception as e:
            print(e)
            nodes.remove(node)
            continue

    if len(nodes) != 0:
        path = None
        if encrypted_file != None:
            path = os.path.join(app.config['UPLOAD_FOLDER'], provided_id+f_ext)
            os.rename( os.path.join(app.config['UPLOAD_FOLDER'], provided_id), os.path.join(app.config['UPLOAD_FOLDER'], provided_id+f_ext) )

        cur.execute("INSERT INTO messages(userid, text, sender, file, provided_id, filename) VALUES(?,?,?,?,?,?)", 
            (contact[0], request.form["message"], "you", encrypted_file, provided_id, path))
        con.commit()
        con.close()

        return {"status": "success", "message": "sent to secondary nodes", "data": {"nodes_count": len(nodes)}}
    else:
        return {"status": "error", "messages": "no nodes available", "data": {"nodes_count": len(nodes)}}
