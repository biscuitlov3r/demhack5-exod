import os
import sqlite3
import requests
import json
import gnupg
import core

gpg = gnupg.GPG()

file = open("config.json", "r")
config = json.loads(file.read())
file.close()

signed_data = gpg.sign("1", keyid=config["mykey_fingerprint"])

password = input("password: ")

for i in config["nodes"]:
    con = sqlite3.connect("db.db")
    cur = con.cursor()
    print(i)
    if i["isprimary"] == 0:
        req = requests.post(i["address"]+"/getmymessages", {
            "key": gpg.export_keys(config["mykey_fingerprint"]),
            "message": signed_data
        })

        res = json.loads(req.text)
        print(req.text)

        if res["status"] == "error":
            continue
        
        contactsnodes = cur.execute("SELECT * FROM nodes").fetchall()

        for i in res["data"]:
            user = cur.execute("SELECT * FROM contacts WHERE keyfingerprint=?", (i["user"][2],)).fetchone()
            if user == None:
                cur.execute("INSERT INTO contacts(pubkey, name, status, keyfingerprint, trusted) VALUES(?,?,?,?,?)",
                    (i["user"][1], None, None, i["user"][2], 0))

                for node in i["nodes"]:
                    ok = True
                    for a in contactsnodes:
                        if node[1] == a[1] and node[2] == a[2]:
                            ok = False
                            break
                    if ok:
                        cur.execute("INSERT INTO nodes(userid, onionaddress, isprimary) VALUES (?,?,?)",
                            (node[1], node[2], node[3]))
                
                user = [i["user"][1], None, None, i["user"][2], 0]

            try:
                decrypted = core.decrypt_string(i["message"][2], password)
                if decrypted["status"] != "decryption ok":
                    continue
            except:
                continue

            cur.execute("INSERT INTO messages(userid, text, sender, file, provided_id) VALUES(?,?,?,?,?)",
                (user[0], decrypted["data"], user[0], None, i["message"][5]))
            con.commit()
            print("commited!")

    con.close()
