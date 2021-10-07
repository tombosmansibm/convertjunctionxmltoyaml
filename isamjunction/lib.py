import xmltodict
import base64
import tempfile

#variables/constants
# junction mapping between xml format and json format
#['MUTAUTHCERT', 'TRANSPARENTPATH', 'TFIMJCTSSO', 'STATEFUL', 'SESSIONCOOKIE']:
mapping_table = {
    "NAME": {"name": "junction_point"},
    "JUCTYPE": {"name": "junction_type"},
    "TRANSPARENTPATH": {"name": "transparent_path_junction", "boolean": True},
    "VIRTUALHOSTJCT": {"name": "virtual_hostname"},
    "STATEFUL": {"name": "stateful_junction", "boolean": True},
    "BASICAUTH": {"name": "basic_auth_mode"},
    "HARDLIMIT": {"name": "junction_hard_limit"},
    "SOFTLIMIT": {"name": "junction_soft_limit"},
    "SESSIONCOOKIE": {"name": "insert_session_cookies", "boolean": True},
    "REQUESTENCODING": {"name": "request_encoding"},
    "TFIMJCTSSO": {"name": "tfim_sso", "boolean": True},
    "MUTAUTHBA": {"name": "enable_basic_auth", "boolean": True},
    "MUTAUTHBAUP": {"name": "username+password"},
    "MUTAUTHCERT": {"name": "mutual_auth", "boolean": True},
    "MUTAUTHCERTLABEL": {"name": "key_label"},
    "CLIENTID": {"name": "remote_http_header"},
    "GSOTARGET": {"name": "gso_resource_group"},
    "FSSOCONFFILE": {"name": "fsso_config_file"},
    "SCRIPTCOOKIE": {"name": "scripting_support", "boolean": True},
    "REMOTEADDRESS": {"name": "client_ip_http", "boolean": True},
    "COOKIENAMEINCLUDEPATH": {"name": "cookie_include_path", "boolean": True},
    "PRESERVECOOKIENAMES": {"name": "preserve_cookie", "boolean": True},
    "JCTHTTP2": {"name": "http2_junction", "boolean": True},
    "RULEREASON": {"name": "authz_rules", "boolean": True},
    "HOST": {"name": "servers.server_hostname"},
    "VIRTHOSTNM": {"name": "servers.virtual_hostname"},
    "PORT": {"name": "servers.server_port"},
    "SERVERDN": {"name": "servers.server_dn"},
    "URLQC": {"name": "servers.query_contents"},
    "LOCALADDRESS": {"name": "servers.local_ip"},
    "UUID": {"name": "servers.server_uuid"},
    "CASEINS": {"name": "servers.case_sensitive_url", "boolean": True},
    "WIN32SUP": {"name": "servers.windows_style_url", "boolean": True}
}

#functions
def f_servers(_isamservers=[], _index=0, _isamkey=None, _isamvalue=None):
    # the syntax here is server.
    # every individual element will have multiple elements (i hope sorted correctly) when there's multiple servers
    if _isamvalue is None:
        return _isamservers
    elif isinstance(_isamvalue , list):
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
        print("SKIP LOCAL JUNCTION")
        return
    junction_name = decodeBase64(base64_message)

    if not junction_name.startswith("/"):
        junction_name = "/"+junction_name
    if junction_name.find("/",1) >= 0:
        # replace / with something else to write the file
        junction_name = junction_name.replace("/","_")
        junction_name = junction_name.replace("_","/",1)

    print("===========\n"+junction_name+"\n===========\n")

    with open(junctionfile) as fd:
        doc = xmltodict.parse(fd.read())
        fd.close()

    #for item in doc.items():
    #    print(item)
    #    print("\n")

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
            jsonvars = mapping_table.get(junctionvars)
            # return an object
            if jsonvars is not None:
                jsonvarn = jsonvars.get('name')
                jsonvarsinglevalue = jsonvars.get('boolean')
            else:
                jsonvarn = None
                jsonvarsinglevalue = False
            #if jsonvarn is not None and junction[1][junctionvars] is not None:
            if jsonvarn is not None:
                if jsonvarn.startswith("servers."):
                    isamservers = f_servers(isamservers, 0, jsonvarn[jsonvarn.rfind(".") + 1:],
                                            junction[1][junctionvars])
                elif junctionvars == 'VIRTUALHOSTJCT':
                    #add virtual_hostname
                    outf.write("virtual_hostname: " + junction[1].get('VIRTHOSTNM') + "\n")
                elif junctionvars == 'SCRIPTCOOKIE':
                    outf.write(jsonvarn + ": yes\n")
                    #write out the type.  junction_cookie_javascript_block
                    # trailer, inhead, onfocus, xhtml10
                    for k in junction[1]:
                        if k.startswith('SCRIPTCOOKIE'):
                            cookieparam = k.replace('SCRIPTCOOKIE','')
                            if cookieparam.lower() == "head":
                                outf.write("junction_cookie_javascript_block: inhead\n")
                            if cookieparam != '':
                                outf.write("junction_cookie_javascript_block: " + cookieparam.lower() + "\n")
                elif junctionvars == 'CLIENTID':
                    #insert_all
                    #insert_pass_usgrcr
                    #do not insert
                    # also, user and groups are seperate entries
                    if junction[1][junctionvars] == 'do not insert':
                        print(">don't insert header")
                    elif junction[1][junctionvars] == 'user':
                        outf.write(jsonvarn+":\n")
                        outf.write("  - iv_user\n")
                    elif junction[1][junctionvars] == 'groups':
                        outf.write(jsonvarn+":\n")
                        outf.write("  - iv_groups\n")
                    elif junction[1][junctionvars] == 'insert_all':
                        outf.write(jsonvarn+":\n")
                        outf.write("  - all\n")
                    else:
                        #look at the end of the string, it indicates user, groups, iv-user-l and/or cred
                        cred = junction[1][junctionvars].split("_")[-1]
                        #print("> cred:" +cred)
                        cred = [cred[i:i + 2] for i in range(0, len(cred), 2)]
                        print("> cred:" + ",".join(cred))
                        outf.write(jsonvarn + ":\n")
                        for val in cred:
                            if val == 'us':
                                outf.write('  - "iv-user"\n')
                            elif val == 'ln':
                                outf.write('  - "iv-user-l"\n')
                            elif val == 'gr':
                                outf.write('  - "iv-groups"\n')
                            elif val == 'cr':
                                outf.write('  - "iv-cred"\n')
                elif junctionvars =='MUTAUTHBAUP':
                    # extract username/password
                    usernamepassword = decodeBase64(junction[1][junctionvars], "utf-8")
                    #usernamepassword = junction[1][junctionvars].decode('base64')
                    print(usernamepassword)
                    theuser = usernamepassword.split("\n")[0]
                    thepw = usernamepassword.split("\n")[1][:-1]  #this is to remove the strange ^ Q character
                    print("username:" + theuser + ", password: "+thepw)
                    outf.write("username: " + theuser + "\n")
                    outf.write("password: " + thepw.strip() + "\n")
                elif junctionvars == "HARDLIMIT" or junctionvars == "SOFTLIMIT":
                    #0 - using global value
                    if junction[1][junctionsvars] == "0":
                       #outf.write(jsonvarn + ": 0 - using global value\n")
                       print("002. Skipping " + junctionvars + " (default)")
                    else:
                       outf.write(jsonvarn + ": " + junction[1][junctionvars] + "\n")

                elif jsonvarsinglevalue is not None and jsonvarsinglevalue:
                    # variables that are just present, and hence are True
                    outf.write(jsonvarn + ": 'yes'\n")
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
