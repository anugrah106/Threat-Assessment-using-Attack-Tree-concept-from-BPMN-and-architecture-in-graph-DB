print("\n\n==========MTP2 Input Automation========\n\n");

generatedFile = open("Input.P", "w")

# attackerLocated(internet).
generatedFile.write("attackerLocated(internet).\n")
generatedFile.write("\n")

def recieveInput(inputString):
    inputStr = input(inputString)
    if(len(inputStr)== 0):
        inputStr = recieveInput(inputString)
    return inputStr

def recieveInputDigit(inputString):
    inputStr = input(inputString)
    if(len(inputStr)== 0):
        inputStr = recieveInputDigit(inputString)
    elif(not inputStr.isdigit()):
        print("Enter the count in digits")
        inputStr = recieveInputDigit(inputString)
    return inputStr

attackGoal = "Enter the attackGoal -  derived node eg: nodeImpact(business_process) = "
goal = recieveInput(attackGoal)

generatedFile.write("attackGoal(" + goal + ").\n")


hypervisors = "Please provide the number of each of the following infrastructure "\
                          "present in the system (Type enter if the quantity is zero): \n"\
                          "Hypervisors = ? "

count_Hypervisors = recieveInputDigit(hypervisors)
vmsCount = "Enter the count of VMs = ?"
count_VMs = recieveInputDigit(vmsCount)

dockerCount = "Dockers (Assuming equal number of workstations) = ? "
count_Dockers = recieveInputDigit(dockerCount)
containerCount = "Enter the number of containers: "
count_Containers = recieveInputDigit(containerCount)
VMCounter = 0
ContainerCounter = 0

for hyp in range(int(count_Hypervisors)):
    genStr = "iaasHostInfo(iaas, hypervisor" + str(hyp + 1) + ", kvmd, kvm).\n"
    generatedFile.write(genStr)
    print("Please enter the number of VMs in Hypervisor-", hyp + 1)
    vms = recieveInputDigit("= ")

    for vm in range(int(vms)):
        VMCounter += 1
        genStr = "iaasGuestInfo(iaas, vm" + str(VMCounter) + ", hypervisor" + str(hyp + 1) + ", kvmd, kvm).\n"
        generatedFile.write(genStr)

generatedFile.write("\n")

for doc in range(int(count_Dockers)):
    genStr = "deploymentInfo(docker" + str(doc + 1) + ", workstation" + str(doc + 1) + ", dockerd, docker).\n"
    generatedFile.write(genStr)
    continfo = recieveInputDigit("How many Containers in this docker" + str(doc + 1) + " :")
    for coninfo in range(int(continfo)):
        genStr1 = "containerInfo(docker" + str(doc + 1) + ", container" + str(coninfo + 1) + ", workstation" + str(
            doc + 1) + ", dockerd, docker).\n"
        generatedFile.write(genStr1)
# info wrt desktop
generatedFile.write("\n")

genStr = "hasAccount(account_desktop, desktop, account_desktop)."
generatedFile.write(genStr)
generatedFile.write("\n")

# info wrt desktop httpd
genStr = "networkServiceInfo(desktop, httpd, httpProtocol, httpPort, www)."
generatedFile.write(genStr)
generatedFile.write("\n")
genStr = "hacl(internet, desktop, httpProtocol, httpPort)."
generatedFile.write(genStr)
generatedFile.write("\n")

print("Please enter no of vulnerabilities for the httpd of desktop")
count_Vul = recieveInputDigit("= ")

for vul in range(int(count_Vul)):
    print("Enter CVE ID (format CVE-2016-7479)")
    cve_Id = recieveInput("= ")
    print("Enter type of exploit(local/remote)")
    exploit_Type = recieveInput("= ")
    print("Enter type of escalation(priv/vm)")
    escalation_Type = recieveInput("= ")
    genStr = "vulExists(desktop, '" + cve_Id + "', httpd, " + exploit_Type + "Exploit, " + escalation_Type + "Escalation)."
    generatedFile.write(genStr)
    generatedFile.write("\n")

# info wrt desktop sshd

generatedFile.write("\n")
genStr = "networkServiceInfo(desktop, sshd, sshProtocol, sshPort, ssh)."
generatedFile.write(genStr)
generatedFile.write("\n")
genStr = "hacl(internet, desktop, sshProtocol, sshPort)."
generatedFile.write(genStr)
generatedFile.write("\n")

print("Please enter no of vulnerabilities for sshd of the desktop")
count_Vul = recieveInputDigit("= ")

for vul in range(int(count_Vul)):
    print("Enter CVE ID (format CVE-2016-7479)")
    cve_Id = recieveInput("= ")
    print("Enter type of exploit(local/remote)")
    exploit_Type = recieveInput("= ")
    print("Enter type of escalation(priv/vm)")
    escalation_Type = recieveInput("= ")
    genStr = "vulExists(desktop, '" + cve_Id + "', sshd, " + exploit_Type + "Exploit, " + escalation_Type + "Escalation)."
    generatedFile.write(genStr)
    generatedFile.write("\n")

print("\nEnter for how many assets do the desktop user has root access for the given application deployed")
asset_Root = recieveInputDigit("= ")
print("Assumed all access will be ssh within the system")
generatedFile.write("\n")

for count in range(int(asset_Root)):
    print("Enter the asset")
    asset = recieveInput("= ")
    print("Enter the priv")
    priv = recieveInput("= ")
    genStr = "hasAccount(account_desktop, " + asset + ", " + priv + ")."
    generatedFile.write(genStr)
    generatedFile.write("\n")
    genStr = "hacl(desktop, " + asset + ", sshProtocol, sshPort)."
    generatedFile.write(genStr)
    generatedFile.write("\n")
    genStr = "networkServiceInfo(" + asset + ", sshd, sshProtocol, sshPort, ssh)."
    generatedFile.write(genStr)
    generatedFile.write("\n")

print("Information with services run on assets")
asset_Service = {}
generatedFile.write("\n")
for i in range(int(count_VMs)):
    print("Enter service being hosted/run on vm" + str(i + 1))
    service = recieveInput("service= ")
    asset_Service.update({service: "vm" + str(i + 1)})
    print(asset_Service)
    protocol = recieveInput("protocol=")
    port = recieveInput("port=")
    protocol_Type = recieveInput("type=")
    genStr = "networkServiceInfo(vm" + str(
        i + 1) + ", " + service + ", " + protocol + ", " + port + ", " + protocol_Type + ")."
    generatedFile.write(genStr)
    generatedFile.write("\n")
# we need to create dictionary to map hardware to service

for i in range(int(count_Containers)):
    print("Enter service being hosted/run on container" + str(i + 1))
    service = recieveInput("service= ")
    ContainerCounter +=1
    asset_Service.update({service: "container" + str(ContainerCounter)})
    print(asset_Service)
    protocol = recieveInput("protocol=")
    port = recieveInput("port=")
    protocol_Type = recieveInput("type=")
    genStr = "networkServiceInfo(container" + str(
        i + 1) + ", " + service + ", " + protocol + ", " + port + ", " + protocol_Type + ")."
    generatedFile.write(genStr)
    generatedFile.write("\n")
# we need to create dictionary to map hardware to service
count_additionalVuls = recieveInputDigit("How many additional vulnerabilities in the system, please enter the count ?")

for vul in range(int(count_additionalVuls)):
    genStr = "vulExists("
    resource = recieveInput("Enter the resource in which vulnerability exists")
    genStr += resource + ", '"
    vul_id = recieveInput("Enter CVE ID (format CVE-2016-7479)")
    genStr += vul_id + "', "
    serv1 = recieveInput("Enter the service/deamon ")
    genStr += serv1 + ", "
    exploit_Type = recieveInput("Enter the exploit type ")
    genStr += exploit_Type + "Exploit, "
    esc = recieveInput("Enter the escalation type")
    genStr += esc + "Escalation)."
    generatedFile.write(genStr+"\n")

print("Enter the Logical flow path of the application"
      " From first task to the last task\n")

print("Enter total no of tasks which represent the successful execution of the application")
count_Tasks = recieveInputDigit("= ")

count_intermediatePaths = recieveInputDigit("How many intermediate paths between first and the last task ?")
genStr_final = "node(business_process, flow, t1, "


def handleIntermediateTask(inputString):
    genStrFlow = "node(" + inputString + ", "
    if (inputString == "t_and"):
        genStrFlow += "and"
    elif (inputString == "t_or"):
        genStrFlow += "or"
    elif (inputString == "t_flow"):
        genStrFlow += "flow"
    else:
        print("Wrong input")
    count1 = recieveInputDigit("Enter the number/count of dependent tasks for {0}: ".format(inputString))
    for jj in range(int(count1)):
        genStrFlow += ", "
        temp1 = recieveInput("Enter the dependent taskNamefor {0}: ".format(inputString))
        if (temp1.startswith("t_flow") or temp1.startswith("t_and") or temp1.startswith("t_or")):
            handleIntermediateTask(temp1)
        genStrFlow += temp1
    genStrFlow += ").\n"
    generatedFile.write(genStrFlow)



for path in range(int(count_intermediatePaths)):
    type = recieveInput("Type (t_and/t_or/t_flow)= ")
    genStr = "node(" + type + ", "
    genStr_final += type
    if(type == "t_and"):
        genStr += "and"
    elif(type == "t_or"):
        genStr += "or"
    elif(type == "t_flow"):
        genStr += "flow"
    else:
        print("Wrong input")

    count = recieveInputDigit("Enter the number/count of dependent tasks for {0}: ".format(type))

    for ii in range(int(count)):
        genStr += ", "
        temp =  recieveInput("Enter the taskName for {0}: ".format(type))
        if(temp.startswith("t_flow") or temp.startswith("t_and") or temp.startswith("t_or")):
            handleIntermediateTask(temp)
        genStr += temp

    genStr += ").\n"
    generatedFile.write(genStr)
    genStr_final += ", "

genStr_final += "t" + str(int(count_Tasks)) + ")."
generatedFile.write(genStr_final + "\n")

print("Details wrt each task dependency on asset layer")

task_Dependency = []
for task in range(int(count_Tasks)):
    print("Enter on how many asset layer dependencies for the task t" + str(task + 1))
    no_Service = recieveInputDigit("=")
    genStr = "node(t" + str(task + 1) + ", and"
    for no in range(int(no_Service)):
        #    task_Dependency.append(input())
        # print("The service dependencies for this task are: ",task_Dependency)
        serv = recieveInput("Enter the service")
        genStr += ", " + serv + ", " + asset_Service[serv]
        #print(genStr)

    generatedFile.write(genStr+").\n")

# to be continued from here
generatedFile.close()
