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
        self.logList = [] # list of exclusively log rules
        self.geo = {} # geo list
        self.logTrack ={} # key = "<extIP>|<localport>" | value = [ pkt_dir | stage = req, next, resp, fin, wait |  nextSeqNo | currBuffer | currLog ]
        self.debug_booleans = {"pass" : "PASSES TEST", "drop" : "FAILS TEST", "deny TCP": "DENIED TCP", "deny DNS": "DENIED DNS"}

        # TODO: Load the firewall rules (from rule_filename) here.

        rules, currLine = open(config['rule'], 'r'), 0
        while currLine != '':
            currLine = rules.readline()
            if currLine != '' and currLine[0] != '\n' and currLine[0] != '%':
                if currLine.split()[0].lower() == "log":
                    self.logList.append(currLine.partition('\n')[0].split())
                else:
                    self.rList.append(currLine.partition('\n')[0].split())
        rules.close()

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
        geotxt.close()

        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        # try:
        verdict = "pass"
        for rule in self.rList:
            verdict = self.apply_rule(pkt, pkt_dir, rule, verdict)
            if verdict == None:
                break
            printD("Rule: {0} ===> {1}".format(rule, self.debug_booleans[verdict]))
 
        # keep track of the packet message if there is a HTTP log
        checkLog = self.checkLog(pkt, pkt_dir)
        if verdict == "pass" and checkLog != "invalid":
                verdict = self.updateLog(pkt, pkt_dir, checkLog)

        # insert check for whether the rule is a pass, drop, deny, or not
        if pkt_dir == PKT_DIR_INCOMING and verdict == "pass":
            # pass packet
            printD("SENT PACKET :D\n")
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING and verdict == "pass":
            # drop packet
            printD("SENT PACKET :D\n")
            self.iface_ext.send_ip_packet(pkt)
        elif verdict == "deny TCP":
            # deny the TCP packet and send a packet back to the proper place
            printD("DENIED TCP PACKET D:")
            rst_pkt = self.deny_TCP(pkt)
            if pkt_dir == PKT_DIR_OUTGOING:
                self.iface_int.send_ip_packet(rst_pkt)
            else:
                self.iface_ext.send_ip_packet(rst_pkt)
        elif verdict == "deny DNS":
            # deny the DNS packet and send a packet to the proper place
            printD("DENIED DNS PACKET D:")
            rst_pkt = self.deny_DNS(pkt, pkt_dir)
            if pkt_dir == PKT_DIR_OUTGOING:
                self.iface_int.send_ip_packet(rst_pkt)
            else:
                self.iface_ext.send_ip_packet(rst_pkt)
        else:
            printD("DID NOT SEND PACKET D:\n")
        # except:
        #     printD("UNEXPECTED ERROR! DROPPING PACKET")

        

    # TODO: You can add more methods as you want.

    """ **************** handle_packet METHODS **************** """

    # applies single rule from the rule list and sets to current verdict if rule doesn't match
    def apply_rule(self, pkt, pkt_dir, rule, current_verdict):
        protocol = self.check_protocol(pkt)
        printD("Assumed protocol: {0}".format(str(protocol)))
        if protocol == None or protocol != rule[1].lower() and rule[1].lower() != "dns":
            printD("RULE DOES NOT APPLY TO PACKET DUE TO TYPE")
            return current_verdict

        DNS_info = None
        if rule[1].lower() == "dns" and protocol == "udp":
            DNS_info= self.getDNS_info(pkt, pkt_dir)
            if DNS_info == None:
                printD("DID NOT MATCH UDP CRITERIA, RETURNING OLD VALUE")
                return current_verdict
            match = self.check_dns(rule[2], DNS_info[0], current_verdict)
        elif rule[1].lower() != "dns":
            match = self.check_ext_IP(pkt, pkt_dir, rule[2]) and self.check_ext_port(pkt, pkt_dir, rule[3])
        else:
            printD("PACKET IS NOT DNS, RETURNING OLD VALUE")
            return current_verdict

        printD("Resulting match: {0}".format(match))
        if rule[0].lower() == "deny" and protocol == "tcp" and match: 
        # match TCP
            return "deny TCP"
        elif rule[0].lower() == "deny" and DNS_info != None and DNS_info[1] == 1 and match: 
        # match DNS
            return "deny DNS"
        elif rule[0].lower() == "pass" and match: 
        # pass packet
            return "pass"
        elif (rule[0].lower() == "drop" or (rule[0].lower() == "deny" and DNS_info != None)) and match:
        # drop packet, or deny DNS is not Qtype == 28
            return "drop"
        else:
            printD("RULE DID NOT MATCH, RETURNING OLD VALUE")
            return current_verdict

    # drops the TCP packet and sends a packet to the src
    def deny_TCP(self, pkt):
        rst = struct.pack('!L', 0x45000028) + struct.pack('!L', 0) + struct.pack('!L', 0x40060000)
        rst += pkt[16 : 20] + pkt[12 : 16] # src | dst port
        rst = rst[0 : 10] + struct.pack("!H", self.compute_Checksum(rst, "IP")) + rst[12 :] # inputting checksum
        head_len = ((ord(pkt[0]) & 0xf) * 4)
        rst += pkt[head_len + 2 : head_len + 4] + pkt[head_len : head_len + 2] # src | dst port
        rst += struct.pack('!L', (struct.unpack('!L', pkt[head_len + 8 : head_len + 12])[0] + 1)) # seq number
        rst += struct.pack('!L', (struct.unpack('!L', pkt[head_len + 4 : head_len + 8])[0] + 1)) # ack number
        rst += struct.pack('!L', 0x50140000) # flags and window
        rst += struct.pack('!L', 0)
        rst = rst[0 : 36] + struct.pack("!H", self.compute_Checksum(rst, "TCP")) + rst[38 :]
        return rst


    # drops DNS packet and sends a packet to its src
    def deny_DNS(self, pkt, pkt_dir):
        rst = struct.pack('!L', 0x45000000) + struct.pack('!L', 0) + struct.pack('!L', 0x40110000)
        rst += pkt[16 : 20] + pkt[12:16]
        head_len = ((ord(pkt[0]) & 0xf) * 4)
        rst += pkt[head_len + 2 : head_len + 4] + pkt[head_len : head_len + 2] # src | dst port
        rst += struct.pack('!L', 0) # placeholder for udp payload length
        rst += pkt[head_len + 8: head_len + 10] + struct.pack('!L', 0x80000001) + struct.pack('!L', 0x10000) + struct.pack('!H', 0) # dns id num + flags
        i = head_len + 20
        while ord(pkt[i]): i += 1
        rst += pkt[head_len + 20 : i + 1] + struct.pack('!L', 0x10001) # Qname, Qtype, Qclass
        rst += pkt[head_len + 20 : i + 1] + struct.pack('!L', 0x10001) + struct.pack('!L', 0x1) + struct.pack('!H', 0x4) + socket.inet_aton("54.173.224.150")
        rst = rst[0:2] + struct.pack('!H', len(rst)) + rst[4:] # inputtting IP total length
        rst = rst[0 : 10] + struct.pack("!H", self.compute_Checksum(rst, "IP")) + rst[12 :] # inputting IP checksum
        rst = rst [0 : 24] + struct.pack("!H", len(rst) - 20) + rst[26:] # inputting UDP length
        return rst

    # returns invalid, if not elligible for log and returns the external IP and local port as a tuple
    def checkLog(self, pkt, pkt_dir):
        try:
            protocol = ord(pkt[9])
            head_len = ((ord(pkt[0]) & 0x0f)*4)
            ext_IP =  socket.inet_ntoa(pkt[12:16])
            extPort = struct.unpack('!H', pkt[head_len : head_len + 2])[0]
            localport = struct.unpack('!H', pkt[head_len + 2  : head_len + 4])[0]
            direction = 1
            if pkt_dir == PKT_DIR_OUTGOING:
                direction = 0
                ext_IP = socket.inet_ntoa(pkt[16:20])
                extPort = struct.unpack('!H', pkt[head_len + 2: head_len + 4])[0]
                localport = struct.unpack('!H', pkt[head_len : head_len + 2])[0]
            if extPort != 80 or protocol != 6:
                printD("invalid port: {0} | protocol {1}".format(extPort, protocol))
                return "invalid"
            printD("valid HTTP: ext IP : {0} | local port: {1}".format(ext_IP, localport))
            return (ext_IP, localport, direction)
        except IndexError:
            return "invalid"


    # updates the log dictionary and prints the information
    def updateLog(self, pkt, pkt_dir, checkLog):
        key = (str(checkLog[0]) + "|" + str(checkLog[1]))
        head_len = ((ord(pkt[0]) & 0xf) * 4)
        tcp_len = ((ord(pkt[head_len + 12]) & 0xf0) >> 4) * 4

        if key not in self.logTrack: # first time seeing request or new request
            printD("inputted new key into dict: {0} | next seqno: {1}".format(key,  struct.unpack("!L", pkt[head_len + 4: head_len + 8])[0] + self.incrementSeq(pkt)))
            self.logTrack[key] = [None, 0, [None, None], "", [str(checkLog[0]), None, None, None, None, "-1"], None]
            self.logTrack[key][2][checkLog[2]] = struct.unpack("!L", (pkt[head_len + 4: head_len + 8]))[0] + self.incrementSeq(pkt)
            # key = "<extIP>|<localport>" | value = [byteCount/Kill | stage = req, resp, log, fin, wait|  nextSeqNo | currBuffer | currLog]
            return "pass"

        if self.logTrack[key][2][checkLog[2]] == None:
            self.logTrack[key][2][checkLog[2]] = struct.unpack("!L", (pkt[head_len + 4: head_len + 8]))[0]


        if struct.unpack("!L", pkt[head_len + 4: head_len + 8])[0] < self.logTrack[key][2][checkLog[2]]: # seqno less than expected
            printD("LOWER SEQNO - passed packet: {0}".format(struct.unpack("!L", pkt[head_len + 4: head_len + 8])[0]))
            printD("info: {0} | stage {1}".format(self.logTrack[key][4], self.logTrack[key][1]))
            return "pass"

        elif struct.unpack("!L", pkt[head_len + 4: head_len + 8])[0] == self.logTrack[key][2][checkLog[2]]: # proper seqno

             # deal with packets remaining after header is finished
            if self.logTrack[key][1] == 3 and self.logTrack[key][0] != "und":
                printD("received after finish packet")

                if self.logTrack[key][5] == checkLog[2]:
                    self.logTrack[key][0] -=  (len(pkt) - head_len - tcp_len)

            # header not finished
            elif self.logTrack[key][0] != "und":

                # printD("packet contents: " +pkt[head_len + tcp_len : ])
                self.logTrack[key][3] += pkt[head_len + tcp_len :] # append header to buffer

                if '\r\n\r\n' in self.logTrack[key][3]: # end of header
                    self.applyLog(pkt, checkLog) # input field into log
                    if self.logTrack[key][0] != None:
                        self.logTrack[key][0] -= len(self.logTrack[key][3].partition('\r\n\r\n')[2]) 
                        self.logTrack[key][5] = checkLog[2]
                    elif self.logTrack[key][1] == 2:
                        self.logTrack[key][0] = "und"
                    self.logTrack[key][1] += 1
                    self.logTrack[key][3] = ""

                if self.logTrack[key][1] == 2: 
                    printD("stage 2")
                    if self.logMatch(pkt, self.logTrack[key][4], checkLog): # if matches rule then write
                        printD("LOG:  " + ' '.join(self.logTrack[key][4]))
                        f = open('http.log', 'a')
                        f.write(' '.join(self.logTrack[key][4]) +"\n")
                        f.flush()
                        f.close()
                    self.logTrack[key][1] += 1

            # if byte count == 0 then we can expect a new packet now
            if self.logTrack[key][0] == 0:
                    printD("resetting fields")
                    self.logTrack[key][0] = None
                    self.logTrack[key][1] = 0
                    self.logTrack[key][3] = ""
                    self.logTrack[key][4] = [checkLog[0], None, None, None, None, "-1"]
                    self.logTrack[key][5] = None
            self.logTrack[key][2][checkLog[2]] += self.incrementSeq(pkt)

            printD("incremented : {0} | passed packet: {1} | bytecount {2} | dir {3}".format(self.incrementSeq(pkt), struct.unpack("!L", pkt[head_len + 4: head_len + 8])[0], self.logTrack[key][0], self.logTrack[key][5]))
            printD("info: {0} | stage {1}".format(self.logTrack[key][4], self.logTrack[key][1]))

            if (ord(pkt[head_len + 13]) & 1) and (ord(pkt[head_len + 13]) & 16) >> 4:
                printD("FINACK received")
                del self.logTrack[key]

            return "pass"

        else: # seqno larger than expected
            printD("dropping packet with seqno: {0} | expecting: {1}".format(struct.unpack("!L", pkt[head_len + 4: head_len + 8])[0], self.logTrack[key][2][checkLog[2]]))
            printD("info: {0} | stage {1}".format(self.logTrack[key][4], self.logTrack[key][1]))
            return "drop"

    # look through the information at hand and see if we can find any fields
    def applyLog(self, pkt, checkLog):
        key = (str(checkLog[0]) + "|" + str(checkLog[1]))

        if self.logTrack[key][1] == 0:
            if "Host:" in self.logTrack[key][3]:
                self.logTrack[key][4][0] = self.logTrack[key][3].split()[self.logTrack[key][3].split().index("Host:") + 1]

            if len(self.logTrack[key][3].split()) > 0:
                self.logTrack[key][4][1] = self.logTrack[key][3].split()[0]

            if len(self.logTrack[key][3].split()) > 1:
                self.logTrack[key][4][2] = self.logTrack[key][3].split()[1]

            if len(self.logTrack[key][3].split()) > 2:
                self.logTrack[key][4][3] = self.logTrack[key][3].split()[2]

        elif self.logTrack[key][1] == 1:
            if len(self.logTrack[key][3].split()) > 0:
                self.logTrack[key][4][4] = self.logTrack[key][3].split()[1]

            if "Content-Length:" in self.logTrack[key][3].split():
                self.logTrack[key][4][5] = self.logTrack[key][3].split()[self.logTrack[key][3].split().index("Content-Length:") + 1]
                self.logTrack[key][0] = int(self.logTrack[key][4][5])




    # given our log fields see if it matches any
    def logMatch(self, pkt, logging, checkLog):
        for rule in self.logList:
            if '*' in rule[2]:
                return rule[2] == '*' or logging[0].lower().endswith(rule[2].lower().partition('*')[2])
            else:
                return logging[0] == rule[2] or checkLog[0] == rule[2]
        return False

    def incrementSeq(self, pkt):
        head_len = ((ord(pkt[0]) & 0xf) * 4)
        tcp_len = ((ord(pkt[head_len + 12]) & 0xf0) >> 4) * 4
        return ((ord(pkt[head_len + 13]) & 2) >> 1) + (ord(pkt[head_len + 13]) & 1) + len(pkt) - head_len - tcp_len


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
        printD("ext_ip rule: {0}".format(rule.lower()))
        printD("IP: {0}".format(repr(IP)))
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
        printD("port: {0}".format(port))
        if rule.lower().partition('\n')[0] == "any":
            return True
        elif '-' in rule:
            return self.port_range(port, rule)
        else:
            return port == int(rule)

    # checks given QName with the DNS rule
    def check_dns(self, rule, QName, current_verdict):
            printD("Checking DNS - Rule {0} | QName: {1}".format(rule, QName))
            if QName == None:
                return current_verdict
            elif '*' not in rule:
                return rule.lower() == QName.lower()
            else:
                return rule == '*' or QName.lower().endswith(rule.lower().partition('*')[2])


    """ **************** UTILITY METHODS **************** """

    # TODO: You may want to add more classes/functions as well.


    # compute the checksum for the TCP or IP header
    def compute_Checksum(self, pkt, pkt_type=None):
        skip = 10
        checksum = 0
        ran = range(0,20)
        if pkt_type == "TCP":
            ran = range (12, 40)
            checksum = 26
            skip = 36
        for i in ran:
            if i != skip and i % 2 != 1:
                checksum += struct.unpack('!H', pkt[i : i + 2])[0]
        checksum = (checksum >> 16) + checksum & 0xffff
        return self.bitFlip(checksum)

    def bitFlip(self, num):
        flipped = 0
        for i in range(0, 16):
            if not num & (1 << i):
                flipped = flipped | (1 << i)
        return flipped


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

    """ returns None if not DNS packet, otherwise returns the QName as a String and Qtype as int, in tuple
    catch statement for fringe case that UDP packet that is very short, and thus while
    loop will exceed size of string and cause index error, in which case it is most
    definitely not an dns packet """
    def getDNS_info(self, pkt, pkt_dir):
        try:
            head_len = ((ord(pkt[0]) & 0x0f) * 4)
            port = struct.unpack('!H', pkt[((ord(pkt[0]) & 0x0f) * 4) : ((ord(pkt[0])& 0x0f) * 4) + 2])[0]
            if pkt_dir == PKT_DIR_OUTGOING:
                port = struct.unpack('!H', pkt[((ord(pkt[0]) & 0x0f)*4) + 2 : ((ord(pkt[0]) & 0x0f) * 4) + 4])[0]

            QDcount, Qname = struct.unpack('!H', pkt [head_len + 12 : head_len + 14] )[0], ""
            i, label_len = head_len + 20, 0
            while ord(pkt[i]):
                if not label_len:
                    label_len = ord(pkt[i]) + 1
                    Qname += '.'
                else:
                    Qname += chr(ord(pkt[i]))
                i, label_len = i + 1, label_len - 1
            Qname = Qname[1:]
            Qtype = struct.unpack('!H', pkt [i + 1 : i + 3])[0]
            Qclass = struct.unpack('!H', pkt[i + 3 :  i + 5])[0]
            printD("port: {0} | Qname: {1} | QDcount: {2} | Qtype: {3} | Qclass: {4}".format(port, Qname, QDcount, Qtype, Qclass))
            if port == 53 and QDcount == 1 and ( Qtype == 1 or Qtype == 28 ) and Qclass == 1:
                return (Qname, Qtype)
            else:
                return None
        except IndexError:
            printD("Threw index error")
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
        printD("slash {0} | comparing IP {1} | rule {2}".format(hex(mask), hex(int(IP[i]) & mask), hex(int(prefix[i]) & mask)))
        return (int(IP[i]) & mask) == (int(prefix[i]) & mask) 

# Quick debug print that can be easy turned on an off
def printD(string="", debug=True):
    if debug:
        print string