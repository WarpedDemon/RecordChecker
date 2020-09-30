import csv
import socket
from SPF2IP import SPF2IP
import numpy as np
import dns.resolver

Domains = []
Data = []
AlreadyDone = []

ClientData = []
MyData = []

with open('pressidium-primary-domains.csv', newline='') as csvfile:
     domainreader = csv.reader(csvfile, delimiter=',', quotechar='|')
     for row in domainreader:
         Domains.append(row[1])

itemCount = -1
for Domain in Domains:
    itemCount += 1
    if itemCount == 0:
        pass
    else:
        # SPF
        try:
            lookup = SPF2IP(Domain)
            records = lookup.GetSPFArray(Domain)
        except Exception as error1:
            print("Loading.")
            pass

        new_DNS_token = False
        newRecord = ""

        for record in records:
            newRecord += record + " | "
            #print(record)
            if str(record) == "include:relay.mailchannels.net":
                new_DNS_token = True

        if new_DNS_token:
            AlreadyDone.append(True)
        else:
            AlreadyDone.append(False)

        if newRecord == "":
            newRecord = "Null"

        # DNS A
        try:
            DNS_record = socket.gethostbyname(Domain)
        except Exception as error2:
            print("Loading..")
            pass

        new_DNS_Record = ""
        AlreadyDoneToken = ""

        for DNS_Record_Item in DNS_record:
            new_DNS_Record += DNS_Record_Item

        if new_DNS_Record == "":
            newDNS_Record = "DNS_Null"

        new_NameServer = ""
        try:
            answers = dns.resolver.query(Domain, 'NS')
        except Exception as error3:
            print("Loading...")
            pass

        HostedOnCloudFlare = False
        Hosted_On_CloudFlare_Token = False

        for answer in answers:
            new_NameServer += " " + str(answer)

            answerString = str(answer)
            compareString = answerString.partition(".")[0]
            if compareString == "beau" or compareString == "chloe" or compareString == "eva" or compareString == "fred":
                #print(compareString)
                Hosted_On_CloudFlare_Token = True

        if Hosted_On_CloudFlare_Token:
            HostedOnCloudFlare = True
        else:
            HostedOnCloudFlare = False

        if new_NameServer == "":
            new_NameServer = "Name_Server_Null"

        HasSPF = None
        if records != []:
            HasSPF = True
        else:
            HasSPF = False

        Data.append(str(
            itemCount) + "," + str(HasSPF) + "," + Domain + "," + newRecord + "," + new_DNS_Record + "," + new_NameServer + "," + str(
            AlreadyDone[itemCount - 1]) + "," + str(HostedOnCloudFlare))

        if AlreadyDone[itemCount - 1]:
            pass
        else:
            if HasSPF:
                if HostedOnCloudFlare:
                    MyData.append(str(itemCount) + "," + Domain + "," + new_DNS_Record + "," + new_NameServer)
                else:
                    ClientData.append(str(itemCount) + "," + Domain + "," + new_DNS_Record + "," + new_NameServer)

        print(str(itemCount)+"/"+str(len(Domains)-1))

'''
for attempt in Data:
    print(attempt)
'''

try:
    np.savetxt("Master.csv", Data, delimiter=",", fmt='%s',
               header="Number,Has SPF,Domain,SPF Record,DNS IPV4,Name Server,Has Pressidium SPF,Hosted On Cloud Flare")

    np.savetxt("Client.csv", ClientData, delimiter=",", fmt='%s',
               header="Number,Domain,Has Pressidium SPF,Name Servers")

    np.savetxt("ToDoList.csv", MyData, delimiter=",", fmt='%s',
               header="Number,Domain,Has Pressidium SPF,Name Servers")
except Exception as error4:
    print("File is open in another program (CSV ERROR)")
    pass

print("Done!")