import re

print("\n\n==========Generate Interaction Rules========\n\n");


def getTaskNode(task):
    for line in lines:
        if ("node(" + task.strip() in line):
            return line.strip('.')


def getAllTaskNodes():
    for line in lines:
        if ("node(" + task.strip() in line):
            taskNodes.append(line.strip("."))
    return taskNodes


def getLastTask(fn):
    # fn = "node(business_process, flow, t1, t_and, t_or, t7)"
    lastTask = fn.split(",")[-1]
    return lastTask.split(")")[0].strip()


def handleBusinessProcessTask(tasksList):
    i = 0
    prev = ""
    tempList = []
    for t in tasksList:
        t = str(t).strip()
        if (i == 0):
            i += 1
            prev = t
            continue
        tempList.append(prev + "," + t)
        prev = t

    for ll in tempList:
        if ("t_" in str(ll).split(",")[-1]):
            logicalTasksFlow.append(ll)


def checkIfNodeCanBeAccessed(tt):
    for line in lines:
        if ("hasAccount(" in line and tt.strip() in line):
            return line.split(",")[1:]


def getNetworServiceInfo(tt):
    for line in lines:
        if ("networkServiceInfo(" + tt.strip() in line):
            return line.strip(".")


def getIaasGuestInfo(tt):
    for line in lines:
        if ("iaasGuestInfo(iaas, " + tt.strip() in line or ("iaasGuestInfo(iaas, " in line and tt in line)):
            return line.strip(".")


def getIaasHostInfo(tt):
    for line in lines:
        if ("iaasHostInfo(iaas, " + tt.strip() in line or ("iaasHostInfo(iaas, " in line and tt in line)):
            return line.strip(".")


def updateDeploymentInfo():
    for line in lines:
        if ("deploymentInfo(" in line):
            docker = line.split(",")[0].split("(")[1].strip()
            workstation = line.split(",")[1].strip()
            depInfo.setdefault(docker, workstation)

        if ("iaasGuestInfo(iaas" in line):
            vm = line.split(",")[1].strip()
            hyper = line.split(",")[2].strip()
            depInfo.setdefault(vm, hyper)
    return depInfo


def updateHypervisorsAndVmsMapping():
    for line in lines:
        if ("iaasGuestInfo(iaas" in line):
            vm = line.split(",")[1].strip()
            hyper = line.split(",")[2].strip()
            if (not HypsAndVms.get(hyper)):
                HypsAndVms.setdefault(hyper, vm)
            else:
                vm1 = str(HypsAndVms.get(hyper))
                HypsAndVms.pop(hyper)
                HypsAndVms.setdefault(hyper, vm1 + "," + vm)


def getlinesContainingContInfo():
    ll = []
    for line in lines:
        if ("containerInfo(" in line):
            ll.append(line)
    return ll


def updateContainerInfoMap():
    for line in lines:
        if ("containerInfo(" in line):
            docker = line.split(",")[0].split("(")[1]
            container = line.split(",")[1].strip()
            if (not containerInfo.get(docker)):
                containerInfo.setdefault(docker, container)
            else:
                container1 = str(containerInfo.get(docker))
                containerInfo.pop(docker)
                containerInfo.setdefault(docker, container1 + "," + str(container))
                # containerInfo.update(docker, str(containerInfo.get(docker))+","+str(container))


def updateVulnerabilities():
    for line in lines:
        if ("vulExists(" in line):
            vulnerabilities.append(line)


def checkIfAnyVulnerabilityPresent(tt):
    for vul in vulnerabilities:
        if (str(tt) in vul):
            return str(vul).strip(".")


def getContainerInfo(tt):
    for line in lines:
        if ("containerInfo(" in line and tt.strip() in line):
            return line.strip(".")


def getDeploymentInfo(tt):
    for line in lines:
        if ("deploymentInfo(" in line and tt.strip() in line):
            return line.strip(".")


# Program Main flow starts here

outputFile = open("InteractionRules.P", "w")

lines = [line.rstrip('\n\n\n') for line in open("Input.P", "r")]
derivedNode = ""
attackGoal = ""
task = ""
taskNodes = []
depInfo = {}  # dictionary containing deployment info: docker1 -> workstation1
containerInfo = {}  # dictionary containing container info: docker -> list of containers
HypsAndVms = {}  # Dictionary of hyps and vms
vulnerabilities = []

for line in lines:
    if ("attackGoal" in line):
        attackGoal = line.strip("\n")
        continue

    if ("/*" in line) or (line.__sizeof__() <= 5):
        continue
    elif (line.rstrip()):
        outputFile.write("primitive(" + line[:-1] + ").\n")
        if ("node(" in line):
            dn = re.match("node(.*?),", line).group(0).strip("node(").strip(",")
            derivedNode += ("derived(nodeImpact(" + dn + ")).\n")

# outputFile.write("\n"+derivedNode)
getAllTaskNodes()
logicalTasksFlow = []
outputFile.write("\n\n#Interaction Rules begin\n\n")
isflowTask = False  # check if it's flow task
tasksSet = set([])  # set of tuples containing service and container eg 'payd, container4'
execCodesList = []  # list which contains execCodes() required

authList = []
print("Enter the no of services which user has root access")
no = input("=")
no = int(no)
print("Please enter the services")
for i in range(no):
    authList.append(input())
print(authList)
s = set(authList)

print("Enter the logical sequence of complete logical task flow ex(t1,t_and(t2,t3),t_or(t_flow(t4,t5),t6),t7)")
seq = input("=")

def updateDependencies(dependencies, flowsList):
    count=0
    while(count < flowsList.__len__()):
        count += 1
        before = flowsList[count].split(",")[0]
        after = flowsList[count].split(",")[1].split(")")[0]
        dependencies.setdefault(after, before)
        count += 1

    return dependencies

flowsList = seq.split("t_flow(")
flowDependencies = {}
updateDependencies(flowDependencies, flowsList)

flowsList = seq.split("t_and(")
andDependencies = {}
updateDependencies(andDependencies, flowsList)


for fn in taskNodes:
    task, op = fn.split(",")[0:2]
    task = task.split("(")[1]
    rule = "interaction_rule((nodeImpact(" + task + "):-\n"
    rule += "\t" + fn.strip(".") + ",\n"
    if ("flow" == op.strip()):
        # special handling for business process task
        handleBusinessProcessTask(fn.split(",")[2:])
        isflowTask = True
        lastTask = getLastTask(fn)
        # taskNode = getTaskNode(lastTask)
        rule += "\t" + "nodeImpact(" + lastTask + ")"
        if (isflowTask):
            rule += "),\n" + "\t\t" \
                             "rule_desc('An impacted child task affects an Process',0.9)\n"
            rule += "\t).\n\n"

        outputFile.write(rule)

    elif ("and" == op.strip() and task == "t_and") or ("or" == op.strip() and task == "t_or"):
        tasksList = fn.split(",")[2:]
        for tsk in tasksList:
            tsk = str(tsk).strip(")")
            rule += "\t" + "nodeImpact(" + tsk.strip() + "),\n"
            print(rule)

        for tt in logicalTasksFlow:
            # print(tt)
            if ("t_and" == str(tt).split(",")[1]):
                first = str(tt).split(",")[0].strip()
                rule += "\t" + "nodeImpact(" + first + "),\n"
                rule += "\t" + getTaskNode("business_process")
                break
            elif ("t_or" == str(tt).split(",")[1]):
                first = str(tt).split(",")[0].strip()
                rule += "\t" + "nodeImpact(" + first + "),\n"
                rule += "\t" + getTaskNode("business_process")
                break
        rule += "),\n" + "\t\t" \
                         "rule_desc('An impacted child task affects an Process',0.9)\n"
        rule += "\t).\n\n"
        outputFile.write(rule)

    elif (not "t_" in task):
        elements = fn.split(",")[2:]
        tasksList = []

        # print (s)
        for i in range(len(elements) - 1):

            if (i % 2 != 0):
                continue
            # print(elements[i])
            if str(elements[i]).strip() in authList:
                # print(elements[i])
                tasksList.append(str(elements[i]).strip() + "," + str(elements[i + 1]).strip(")"))
                # if tasksList[0] in authList:
                # print (tasksList)
                # print("hi")
                tasksSet.update(tasksList)
        # print(tasksList)
        for tt in tasksList:
            rule += "\n\t" + "nodeImpact(" + str(tt).strip() + "),"
            derivedNode += ("derived(nodeImpact(" + str(tt) + ")).\n")
            # print(str(tt))

        if andDependencies.get(task):
            rule += "\n\t" + "nodeImpact(" + andDependencies.get(task) + "),\n"
        elif flowDependencies.get(task):
            rule += "\n\t" + "nodeImpact(" + flowDependencies.get(task) + ")),"
        rule += "\n" + "\t\t" \
                       "rule_desc('An impacted child task affects an Process',0.9)\n"
        rule += "\t).\n\n"
        outputFile.write(rule)

for tt in tasksSet:
    # print("hi")
    # print(tt)
    # print("he")
    t = str(tt).split(",")[1]
    # print(t)
    privileges = checkIfNodeCanBeAccessed(str(t).strip())  # check if hasAccount() info present and extract

    if (privileges):
        kk = getNetworServiceInfo(t)
        # print("jj")
        # print(kk)
        rule = "interaction_rule((nodeImpact(" + str(tt) + "):-"
        # print("kk")
        derivedNode += ("derived(nodeImpact(" + str(tt) + ")).\n")
        # print("k1k1")
        rule += "\n\t" + kk + ","
        rule += "\n\texecCode(" + privileges[0].strip() + "," + privileges[1].strip(").")
        rule += ")),"
        rule += "\n" + "\t\t" \
                       "rule_desc('An impacted child task affects a Process',0.9)\n"
        rule += "\t).\n\n"
        outputFile.write(rule)

    else:
        kk = getNetworServiceInfo(t)
        # print("ll")
        # print(kk)
        rule = "interaction_rule((nodeImpact(" + str(tt) + "):-"
        rule += "\n\t" + kk + ","
        var_execCode = "execCode(" + t.strip() + ",root"
        execCodesList.append(var_execCode + ")")
        # print("H")
        # print(var_execCode)
        # print("k")
        derivedNode += ("derived(" + var_execCode + ")).\n")
        # print(derivedNode)

        # outputFile.write("\n"+derivedNode)
        rule += "\n\t" + var_execCode
        rule += ")),"
        rule += "\n" + "\t\t" \
                       "rule_desc('An impacted child task affects a Process',0.9)\n"
        rule += "\t).\n\n"
        outputFile.write(rule)

# getContainerInfoMap()
# print(containerInfo)
# print(getDeploymentInfo())
# write the ineraction rule for each execCode
updateDeploymentInfo()
newExecCodes = []
updateVulnerabilities()  # update vulnerabilities

for execCode in execCodesList:
    # print(execCode)
    tt = str(execCode).split(",")[0].split("(")[1].strip()
    # print(tt)
    # print("hi")
    if ("container" in tt):
        rule = "interaction_rule((" + str(execCode) + "):-"
        containerInfo = getContainerInfo(tt)
        rule += "\n\t" + containerInfo + ","
        # extract which docker contains this container
        docker = containerInfo.split(",")[0].split("(")[1]
        if (depInfo.get(docker)):
            var = "execCode(" + depInfo.get(docker) + ", docker"
            newExecCodes.append(var + ")")
            # print(var)
            rule += "\n\t" + var
            # print(rule)
            rule += ")),"
            rule += "\n" + "\t\t" \
                           "rule_desc('An impacted child task affects a Process',0.7)\n"
            rule += "\t).\n\n"

            derivedNode += ("derived(" + var + ")).\n")
            # print(derivedNode)

            # outputFile.write("\n"+derivedNode)

            outputFile.write(rule)

    # if execCode line contains vm or hypervisor, then extract iaasGuestInfo
    if ("vm" in tt):
        rule = "interaction_rule((" + str(execCode) + "):-"
        rule += "\n\t" + getIaasGuestInfo(tt)
        vul = checkIfAnyVulnerabilityPresent(tt)
        if (vul):
            rule += "\n\t" + vul + ","

        if (depInfo.get(tt)):
            var = "execCode(" + depInfo.get(tt) + ", kvm"
            newExecCodes.append(var + ")")
            rule += "\n\t" + var
            rule += ")),"
            rule += "\n" + "\t\t" \
                           "rule_desc('An impacted child task affects a Process',0.7)\n"
            rule += "\t).\n\n"
            derivedNode += ("derived(" + var + ")).\n")
            # print(derivedNode)

            # outputFile.write("\n"+derivedNode)
            outputFile.write(rule)

    if ("hypervisor" in tt):
        rule = "interaction_rule((" + str(execCode) + "):-"
        rule += "\n\t" + getIaasGuestInfo(tt) + ","
        rule += "\n\t" + getIaasHostInfo(tt) + ","
        vul = checkIfAnyVulnerabilityPresent(tt)
        if (vul):
            rule += "\n\t" + vul + ","
        updateHypervisorsAndVmsMapping()  # updates HypsAndVms{} as well
        vms = HypsAndVms.get(tt)
        if (str(vms).split(",").__sizeof__() == 1):
            if (checkIfNodeCanBeAccessed(vms)):
                var = "execCode(" + vms + ", kvm"
                newExecCodes.append(var + ")")
                rule += "\n\t" + var
                rule += ")),"
                rule += "\n" + "\t\t" \
                               "rule_desc('An impacted child task affects a Process',0.7)\n"
                rule += "\t).\n\n"
                derivedNode += ("derived(" + var + ")).\n")
                # print(derivedNode)

                # outputFile.write("\n"+derivedNode)
                outputFile.write(rule)

for execCode in newExecCodes:
    tt = str(execCode).split(",")[0].split("(")[1].strip()
    if ("workstation" in tt):
        rule = "interaction_rule((" + str(execCode) + "):-"
        containerInfo = getContainerInfo(tt)
        if (containerInfo):
            rule += "\n\t" + containerInfo + ","
        deploymentInfo = getDeploymentInfo(tt)
        if (deploymentInfo):
            rule += "\n\t" + deploymentInfo + ","
        vul = checkIfAnyVulnerabilityPresent(tt)
        if (vul):
            rule += "\n\t" + vul

        rule += ")),"
        rule += "\n" + "\t\t" \
                       "rule_desc('An impacted child task affects a Process',0.7)\n"
        rule += "\t).\n\n"
        outputFile.write(rule)

    if ("hypervisor" in tt):
        rule = "interaction_rule((" + str(execCode) + "):-"
        rule += "\n\t" + getIaasGuestInfo(tt).strip() + ","
        rule += "\n\t" + getIaasHostInfo(tt).strip() + ","
        vul = checkIfAnyVulnerabilityPresent(tt)
        if (vul):
            rule += "\n\t" + vul + ","
        vms = HypsAndVms.get(tt)
        if (str(vms).split(",").__sizeof__() > 0):
            for vm in str(vms).split(","):
                if (checkIfNodeCanBeAccessed(vm)):
                    var = "execCode(" + vm + ", kvm"
                    rule += "\n\t" + var
        rule += ")),"
        rule += "\n" + "\t\t" \
                       "rule_desc('An impacted child task affects a Process',0.7)\n"
        rule += "\t).\n\n"
        outputFile.write(rule)

outputFile.write("\n" + derivedNode)

outputFile.close()
