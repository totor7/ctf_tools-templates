 #!usr/bin/env python
# coding:utf-8

#####################################################################################################################################
#   THIS SCRIPT IS SPECIFICALLY CREATED FOR A REVERSE BLIND SQL CHALLENGE WE GET THE NETWORK LOGS. LOGS HAD THE FOLLOWING FORMAT:   #
#  <ip> - - [dd/mmm/yyyy:HH:MM:SS +xxxx] "GET /admin/?action=membres&order=<Command in hexadecimal value> HTTP/1.1" 200 832 "-" "-" #
# Commands allowed time based blind sql injection
#
# IT SHOULD BE   #
# ADAPTED TO YOUR NEEDS BEFOR USING IT                                                         #
###############################################################################################


import pwn
import re
import base64
import codecs
import binascii

parsed=[]

#READ LOGS
with open('logs', 'r') as fp:
    Lines = fp.readlines()

#Parse Lines for interpretation
for line in Lines:
    #parseTime: To be oviously adapted to your case
    time = re.split("[:+\s]",re.search("\[18.*0200\]",line)[0])
    time = int(time[2])*60 + int (time[3])

    # parseSQLrequest: To be oviously adapted to your case
    if(re.search("%3D",line)):
        parsedline = re.search("order=.*%3D", line)[0][6:-3].encode('utf-8')
    else:
        parsedline = re.search("order=.*HTTP", line)[0][6:-4].encode('utf-8')
    missing_padding = 4 -len(parsedline) % 4
    if missing_padding:
        parsedline += b'=' * missing_padding

    parsedline = base64.b64decode(parsedline)
    parsed.append([parsedline,time])

    
res=""
excepctions_to_be_handled=[]
for i in range(len(parsed)-1):
    delta = parsed[i+1][1]-parsed[i][1]
    if i%4==0:
        res+='0'
    
    if i%4==3:
        if delta == 2:
            res += '0'
        elif delta == 4 :
            res+= '1'
        else:
            #####################################
            #   USEFUL NOTES ON THIS USE CAS    #
            #####################################
            # sqli3 BIN() command reads the ascci caracteres in binary starting by the NON NULL MOST SIGNIFICATN BIT
            # Noting that an ASCII alphanumerical value in binary always starts with a 0, it is worth noticing that 2nd most significant bit is also import 
            # A 0 on the second bit means we are dealing with a number and a 1 with a letter.
            # Make sure your code takes this into account while reversing or performing a blind sql which uses BIN()
            excepctions_to_be_handled.append(len(res))
            res = res[:-6]+ '0' + res[-6:] 

    else:
        if delta == 0:
            res += '00'
        elif delta == 2 :
            res+= '01'
        elif delta == 4 :
            res+= '10'
        elif delta == 6 :
            res+= '11' 
        else :
            print('SEEMS THAT YOU HAVE FORGOTEN SOME USES CASES?')


def string_decode(input, length=8):
    input_l = [input[i:i+length] for i in range(0,len(input),length)]
    return ''.join([chr(int(c,base=2)) for c in input_l])

result = string_decode(res)[:-1]
print(result)

return result
