import xmltodict
import base64
import tempfile

#variables/constants
# junction mapping between xml format and json format
mapping_table = {
    "NAME": "junction_point",
    "JUCTYPE": "junction_type",
    "TRANSPARENTPATH": "transparent_path_junction",
    "STATEFUL": "stateful_junction",
    "BASICAUTH": "basic_auth_mode",
    "HARDLIMIT": "junction_hard_limit",
    "SOFTLIMIT": "junction_soft_limit",
    "SESSIONCOOKIE": "insert_session_cookies",
    "REQUESTENCODING": "request_encoding",
    "TFIMJCTSSO": "tfim_sso",
    "MUTAUTHBA": "enable_basic_auth",
    "MUTAUTHBAUP": "username+password",
    "MUTAUTHCERT": "mutual_auth",
    "MUTAUTHCERTLABEL": "key_label",
    "CLIENTID": "remote_http_header",
    "HOST": "servers.server_hostname",
    "VIRTHOSTNM": "servers.virtual_hostname",
    "PORT": "servers.server_port",
    "SERVERDN": "servers.server_dn",
    "URLQC": "servers.query_contents",
    "LOCALADDRESS": "servers.local_ip",
    "UUID": "servers.server_uuid"
}

#functions
def f_servers(_isamservers=[], _index=0, _isamkey=None, _isamvalue=None):
    # the syntax here is server.
    # every element will have multiple elements (i hope sorted correctly) when there's multiple elements
    # TODO: the logic here is flawed in the sense that if there's more than 1 server, it will depend on the order in the junction.xml if it works or not
    if _isamvalue is None:
        return _isamservers
    elif isinstance(_isamvalue , list):
        print("isamvalue is a list")
        for i, val in enumerate(_isamvalue):
            if not val is None:
                if len(_isamservers) > i:
                    _isamservers[i].update({_isamkey: val})
                else:
                   _isamservers.append({_isamkey: val})
    else:
        if len(_isamservers) > _index:
            # exists
            _isamservers[_index].update({_isamkey: _isamvalue})
        else:
            _isamservers.append({_isamkey: _isamvalue})
    return _isamservers

def decodeBase64(input, encoding='utf-8'):
    #utf-8, ascii, ...
    base64_bytes = input.encode(encoding)
    message_bytes = base64.b64decode(base64_bytes)
    decoded = message_bytes.decode(encoding)
    return decoded

def f_processJunction(junctionfile):
    # base64 filename?
    base64_message = junctionfile[junctionfile.rfind('/') + 1:junctionfile.rfind('.')]
    if base64_message == 'Lw==':
        #skip this, this is the local junction
        return
    junction_name = decodeBase64(base64_message)

    print("===========\n"+junction_name+"\n===========\n")

    with open(junctionfile) as fd:
        doc = xmltodict.parse(fd.read())
        fd.close()

    for item in doc.items():
        print(item)
        print("\n")

    # open a file for writing
    outfilename = tempfile.gettempdir() + junction_name + ".yaml"
    outf = open(outfilename, "w", encoding='iso-8859-1')
    outf.writelines("---\n")
    for junction in doc.items():
        # translate to a json/yaml object
        # find the item that's in the junction file, and map it to an item in config
        #print('Number of elements: ' + str(len(junction)))
        isamservers = []
        for junctionvars in junction[1]:
            jsonvarn = mapping_table.get(junctionvars)
            #if jsonvarn is not None and junction[1][junctionvars] is not None:
            if jsonvarn is not None:
                if jsonvarn.startswith("servers."):
                    isamservers = f_servers(isamservers, 0, jsonvarn[jsonvarn.rfind(".") + 1:],
                                            junction[1][junctionvars])
                elif junctionvars == 'MUTAUTHBA':
                    # BASICAUTH MUTUAL
                    print("> Mutual auth ba")
                    outf.write(jsonvarn + ": true\n")
                elif junctionvars == 'CLIENTID':
                    #insert_all
                    #insert_pass_usgrcr
                    #do not insert
                    if junction[1][junctionvars] == 'do not insert':
                        print(">don't insert header")
                    elif junction[1][junctionvars] == 'insert_all':
                        outf.write(jsonvarn+":\n")
                        outf.write("  - all\n")
                    else:
                        #look at the end of the string, it indicates user, group and/or cred
                        cred = junction[1][junctionvars].split("_")[-1]
                        #print("> cred:" +cred)
                        cred = [cred[i:i + 2] for i in range(0, len(cred), 2)]
                        print("> cred:" + ",".join(cred))
                        outf.write(jsonvarn + ":\n")
                        for val in cred:
                            if val == 'us':
                                outf.write('  - "iv-user"\n')
                            elif val == 'gr':
                                outf.write('  - "iv-group"\n')
                            elif val == 'cr':
                                outf.write('  - "iv-cred"\n')
                elif junctionvars =='MUTAUTHBAUP':
                    # extract username/password
                    usernamepassword = decodeBase64(junction[1][junctionvars], "utf-8")
                    #usernamepassword = junction[1][junctionvars].decode('base64')
                    print(usernamepassword)
                    theuser = usernamepassword.split("\n")[0]
                    thepw = usernamepassword.split("\n")[1][:-1]  #this is to remove the strange ^ Q character
                    print("user:" + theuser + ", password: "+thepw)
                    outf.write("user: " + theuser + "\n")
                    outf.write("password: " + thepw.strip() + "\n")
                elif junctionvars in ['MUTAUTHCERT', 'TRANSPARENTPATH', 'TFIMJCTSSO', 'STATEFUL', 'SESSIONCOOKIE']:
                    # variables that are just present
                    outf.write(jsonvarn + ": yes\n")
                else:
                    if junction[1][junctionvars] is not None:
                        print(junctionvars + ": " + junction[1][junctionvars])
                        outf.write(jsonvarn + ": " + junction[1][junctionvars] + "\n")
                    else:
                        print("002. Skipping " + junctionvars)
            else:
                print("001. Skipping " + junctionvars)

    # write out servers
    print(isamservers)
    outf.write("servers:\n")
    for r in isamservers:
        outf.write("  -\n")
        for ser in r:
            outf.write("    ")
            outf.write(ser + ": " + r[ser])
            outf.write("\n")
    outf.close()

    #print
    print("\n\nWRITTEN TO: " + outfilename)
