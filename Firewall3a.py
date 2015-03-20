    #!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import sys, socket, struct

    # TODO: Feel free to import any Python standard moduless as necessary.
    # (http://docs.python.org/2/library/)
    # You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rList = [] # rule list
        self.geo = {} # geo list
        self.debug_booleans = {True : "PASSES TEST", False : "FAILS TEST"}

        # TODO: Load the firewall rules (from rule_filename) here.

        rules, currLine = open(config['rule'], 'r'), 0
        while currLine != '':
            currLine = rules.readline()
            if currLine != '' and currLine[0] != '\n' and currLine[0] != '%':
                self.rList.append(currLine.partition('\n')[0].split())

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.

        geotxt, currLine = open('geoipdb.txt'), 0
        while currLine != []:
            currLine = geotxt.readline().split()  # split into [ <IP range1>, <IP range2>, geo ]
            if currLine == []:
                break
            elif currLine[2].upper() in self.geo: # add IP range to dict
                self.geo[currLine[2].upper()] += [ (currLine[0], currLine[1]) ]
            else: # if geo doesn't exist in dictionary add it
                self.geo[currLine[2].upper()] = [ (currLine[0], currLine[1]) ]


        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        try:
            verdict = True
            for rule in self.rList:
                verdict = self.apply_rule(pkt, pkt_dir, rule, verdict)
                if verdict == None:
                    break
                self.printD("Rule: {0} ===> {1}".format(rule, self.debug_booleans[verdict]))

            if pkt_dir == PKT_DIR_INCOMING and verdict:
                self.printD("SENT PACKET :D\n")
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING and verdict:
                self.printD("SENT PACKET :D\n")
                self.iface_ext.send_ip_packet(pkt)
            else:
                self.printD("DID NOT SEND PACKET D:\n")
        except:
            self.printD("UNEXPECTED ERROR! DROPPING PACKET")

        

    # TODO: You can add more methods as you want.

    """ **************** handle_packet METHODS **************** """

    # applies single rule from the rule list and sets to current verdict if rule doesn't match
    def apply_rule(self, pkt, pkt_dir, rule, current_verdict):
        protocol = self.check_protocol(pkt)
        self.printD("Assumed protocol: {0}".format(str(protocol)))
        if protocol == None or protocol != rule[1].lower() and rule[1].lower() != "dns":
            self.printD("RULE DOES NOT APPLY TO PACKET DUE TO TYPE")
            return current_verdict

        verdict = False
        Qname = None

        if rule[1].lower() == "dns" and protocol == "udp":
            Qname = self.getQname(pkt, pkt_dir)
            if Qname == None:
                self.printD("DID NOT MATCH UDP CRITERIA, RETURNING OLD VALUE")
                return current_verdict
            match = self.check_dns(rule[2], Qname, current_verdict)
        elif rule[1].lower() != "dns":
            match = self.check_ext_IP(pkt, pkt_dir, rule[2]) and self.check_ext_port(pkt, pkt_dir, rule[3])
        else:
            self.printD("PACKET IS NOT DNS, RETURNING OLD VALUE")
            return current_verdict

        self.printD("Resulting match: {0}".format(match))
        if rule[0].lower() == "pass" and match:
            return True
        elif rule[0].lower() == "drop" and match:
            return False
        else:
            self.printD("RULE DID NOT MATCH, RETURNING OLD VALUE")
            return current_verdict


    """ **************** apply_rule METHODS **************** """

    # returns the type of the packet, returns False if not one of the packets covered in the project
    def check_protocol(self, pkt):
        if ord(pkt[9]) == 6:
            return "tcp"
        elif ord(pkt[9]) == 17:
            return "udp"
        elif ord(pkt[9]) == 1:
            return "icmp"
        else:
            return None

    # checks external IP address rule
    def check_ext_IP(self, pkt, pkt_dir, rule):
        IP = socket.inet_ntoa(pkt[12:16])
        if pkt_dir == PKT_DIR_OUTGOING:
            IP = socket.inet_ntoa(pkt[16:20])
        self.printD("ext_ip rule: {0}".format(rule.lower()))
        self.printD("IP: {0}".format(repr(IP)))
        if rule.lower() == "any":
            return True
        elif rule.upper() in self.geo:
            return self.getGeo(IP, self.geo[rule.upper()])
        elif '/' in rule:
            return self.IP_prefix(IP, rule)
        else:
            return self.compare_IP(IP, rule) == 0

    # checks external port rule
    def check_ext_port(self, pkt, pkt_dir, rule):
        port = struct.unpack('!H', pkt[((ord(pkt[0]) & 0x0f) * 4) : ((ord(pkt[0])& 0x0f) * 4) + 2])[0]
        if pkt_dir == PKT_DIR_OUTGOING:
            port = struct.unpack('!H', pkt[((ord(pkt[0]) & 0x0f)*4) + 2 : ((ord(pkt[0]) & 0x0f) * 4) + 4])[0]
        self.printD("port: {0}".format(port))
        if rule.lower().partition('\n')[0] == "any":
            return True
        elif '-' in rule:
            return self.port_range(port, rule)
        else:
            return port == int(rule)

    # checks given QName with the DNS rule
    def check_dns(self, rule, QName, current_verdict):
            self.printD("Checking DNS - Rule {0} | QName: {1}".format(rule, QName))
            if QName == None:
                return current_verdict
            elif '*' not in rule:
                return rule.lower() == QName.lower()
            else:
                return rule == '*' or QName.lower().endswith(rule.lower().partition('*')[2])


    """ **************** UTILITY METHODS **************** """

    # TODO: You may want to add more classes/functions as well.

    # Quick debug print that can be easy turned on an off
    def printD(self, string, once=False, debug=False):
        if debug:
            print string

    # Given an IP and country, find out using binary search whether the IP is in range
    def getGeo(self, IP, IPList):
        minIP, maxIP = 0, len(IPList) - 1
        mid = int(round((maxIP + minIP) / 2))
        while self.compare_IP(IP, IPList[minIP][0]) != -1 and self.compare_IP(IP, IPList[maxIP][1]) != 1:
            mid = int(round((maxIP + minIP) / 2))
            if self.IP_range(IP, IPList[mid]):
                return True
            elif self.compare_IP(IP, IPList[mid][0]) == -1:
                maxIP = mid - 1
            else:
                minIP = mid + 1
        return False

    """ returns None if not DNS packet, otherwise returns the QName as a String,
    catch statement for fringe case that UDP packet that is very short, and thus while
    loop will exceed size of string and cause index error, in which case it is most
    definitely not an dns packet """
    def getQname(self, pkt, pkt_dir):
        try:
            head_len = ((ord(pkt[0]) & 0x0f) * 4)
            port = struct.unpack('!H', pkt[((ord(pkt[0]) & 0x0f) * 4) : ((ord(pkt[0])& 0x0f) * 4) + 2])[0]
            if pkt_dir == PKT_DIR_OUTGOING:
                port = struct.unpack('!H', pkt[((ord(pkt[0]) & 0x0f)*4) + 2 : ((ord(pkt[0]) & 0x0f) * 4) + 4])[0]

            QDcount, Qname = struct.unpack('!H', pkt [head_len + 12 : head_len + 14] )[0], ""
            i, label_len = head_len + 20, 0
            while ord(pkt[i]):
                if  not label_len:
                    label_len = ord(pkt[i]) + 1
                    Qname += '.'
                else:
                    Qname += chr(ord(pkt[i]))
                i, label_len = i + 1, label_len - 1
            Qname = Qname[1:]
            Qtype = struct.unpack('!H', pkt [i + 1 : i + 3])[0]
            Qclass = struct.unpack('!H', pkt[i + 3 :  i + 5])[0]
            self.printD("port: {0} | Qname: {1} | QDcount: {2} | Qtype: {3} | Qclass: {4}".format(port, Qname, QDcount, Qtype, Qclass))
            if port == 53 and QDcount == 1 and ( Qtype == 1 or Qtype == 28 ) and Qclass == 1:
                return Qname
            else:
                return None
        except IndexError:
            self.printD("Threw index error")
            return None


    # Compares each part of IP and returns:
    # -1  if IP1 < IP2
    #  0  if IP1 = IP2
    #  1  if IP1 > IP2
    def compare_IP(self, IP1, IP2):
        if IP1 == IP2:
            return 0
        split_IP1, split_IP2, i = IP1.split('.'), IP2.split('.'), 0
        while i < 4 and split_IP1[i] == split_IP2[i]:
            i += 1
        if int(split_IP1[i]) < int(split_IP2[i]):
            return -1
        else:
            return 1

    # checks to see whether the given IP is in the interval ( in tuple form )
    def IP_range(self, IP, span):
        return (self.compare_IP(IP, span[0]) == 1 and self.compare_IP(IP, span[1]) == -1) or self.compare_IP(IP, span[0]) == 0 or self.compare_IP(IP, span[1]) == 0

    # checks port range
    def port_range(self, port, span):
        portSpan = span.split('-')
        return int(portSpan[0]) >= port and port <= int(portSpan[1])

    # checks to see if given prefix matches given IP
    def IP_prefix(self, IP, prefix):
        slash, i = int(prefix.partition('/')[2]), 0
        IP, prefix = IP.split('.'), prefix.partition('/')[0].split('.')
        while slash >= 8:
            if IP[i] != prefix[i]:
                return False
            i, slash = i + 1, slash - 8
        if slash == 0:
            return True
        mask = (0xff << (8 - slash)) & 0xff
        self.printD("slash {0} | comparing IP {1} | rule {2}".format(hex(mask), hex(int(IP[i]) & mask), hex(int(prefix[i]) & mask)))
        return (int(IP[i]) & mask) == (int(prefix[i]) & mask) 
