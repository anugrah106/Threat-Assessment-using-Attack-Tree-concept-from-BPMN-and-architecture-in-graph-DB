import sys
import re
import ast
import queue
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict 

count = 0
mapping = {}
listOfPath = []

class Graph: 
   
    def __init__(self,vertices): 
        self.V= vertices  
        self.graph = defaultdict(list)  
   
    def addEdge(self,u,v): 
        self.graph[u].append(v) 

    def printAllPathsUtil(self, u, d, visited, path, file1): 
        visited[u]= True
        path.append(u+1)  
        if u == d: 
            # print(path)
            s = ""
            s = s+"["
            for i in range(len(path)):
                s = s + str(path[i])
                s = s + ", "
            s = s[:-2]
            s = s+"]"
            # print(s)
            file1.write(s+"\n")
        else: 
            for i in self.graph[u]: 
                if visited[i]==False: 
                    self.printAllPathsUtil(i, d, visited, path, file1) 

        path.pop() 
        visited[u]= False

    def printAllPaths(self,s, d): 
        global listOfPath
        visited =[False]*(self.V) 
        path = []
        file1 = open("temp2", "w")
        self.printAllPathsUtil(s, d,visited, path, file1)
        file1.close()

    def isNotVisited(self, x, path):
        size = len(path)
        for i in range(size):
            if(path[i] == x):
                return 0
        return 1
    
    # def findPaths(self, src, dst, v):
    #     q = queue.Queue(maxsize=20)
    #     path = []
    #     path.append(src)
    #     q.put(src)
    #     while(not q.empty()):



def creatingTempFile(file, file1):
    st = "</bpmn:task>"
    st1 = "</bpmn:endEvent>"
    st2 = "</bpmn:startEvent>"
    st3 = "</bpmn:intermediateCatchEvent>"
    st4 = "</bpmn:userTask>"
    st5 = "</bpmn:serviceTask>"
    st6 = "</task>"
    st7 = "</startEvent>"
    st8 = "</ednEvent>"
    st9 = "</intermediateCatchEvent>"
    st10 = "</userTask>"
    st11 = "</serviceTask>"
    for readline in file:
        line = readline.strip()
        readline = readline.rstrip()
        
        if line == st or line == st1 or line == st2 or line == st3 or line == st4 or line == st5 or line == st6 or line == st7 or line == st8 or line == st9 or line == st10 or line == st11:
            file1.write(readline+", \n")
        else:
            readline = readline.replace("</bpmn:outgoing>","</bpmn:outgoing>*")
            readline = readline.replace("</bpmn:incoming>","</bpmn:incoming>^")
            file1.write(readline+"\n")

def dataCleaning(data, i):
    global mapping
    global count
    task = ""
    if i == "0":
        #StartTask
        for item1 in data:
            temp1 = re.findall(r"startEvent id=\"[a-z A-Z \- _ 0-9]*\"", item1)
            for item2 in temp1:
                temp2 = re.findall(r"\"[a-z A-Z \- _ 0-9]*\"", item2)
                for item3 in temp2:
                    task = item3
                    task = task.strip('"')
                    count = count + 1    
                    mapping[task] = count

    elif i == "1":
        #Task    
        for item1 in data:
            temp1 = re.findall(r"id=\"[a-z A-Z \- _ 0-9]*\"", item1)
            for item2 in temp1:
                temp2 = re.findall(r"\"[a-z A-Z \- _ 0-9]*\"", item2)
                for item3 in temp2:
                    task = item3
                    task = task.strip('"')
                    count = count + 1    
                    mapping[task] = count
    elif i == "2":
        #intermediateCatchEvent
        for item1 in data:
            temp1 = re.findall(r"intermediateCatchEvent id=\"[a-z A-Z \- _ 0-9]*\"", item1)
            for item2 in temp1:
                temp2 = re.findall(r"\"[a-z A-Z \- _ 0-9]*\"", item2)
                for item3 in temp2:
                    task = item3
                    task = task.strip('"')
                    count = count + 1    
                    mapping[task] = count
    else:
        #endEvent
        for item1 in data:
            temp1 = re.findall(r"endEvent id=\"[a-z A-Z \- _ 0-9]*\"", item1)
            for item2 in temp1:
                temp2 = re.findall(r"\"[a-z A-Z \- _ 0-9]*\"", item2)
                for item3 in temp2:
                    task = item3
                    task = task.strip('"')
                    count = count + 1    
                    mapping[task] = count

def getTask(content):
    global mapping
    data1 = re.findall(r"<[a-z :]*startEvent[A-Z a-z \" = _ 0-9 \s < > * \-  # ^ : \/]*<\/[a-z :]*startEvent>", content)
    # print(data1)
    dataCleaning(data1, "0")
    data2 = re.findall(r"<[a-z :]*task[A-Z a-z \" = _ 0-9 \s < > * \-  # ^ : \/]*<\/[a-z :]*task>", content)
    dataCleaning(data2, "1")
    data2 = re.findall(r"<[a-z :]*userTask[A-Z a-z \" = _ 0-9 \s < > * \-  # ^ : \/]*<\/[a-z :]*userTask>", content)
    dataCleaning(data2, "1")
    data2 = re.findall(r"<[a-z :]*serviceTask[A-Z a-z \" = _ 0-9 \s < > * \-  # ^ : \/]*<\/[a-z :]*serviceTask>", content)
    dataCleaning(data2, "1")
    data3 = re.findall(r"<[a-z :]*intermediateCatchEvent[A-Z a-z \" = _ 0-9 \s < > * \-  # ^ : \/]*<\/[a-z :]*intermediateCatchEvent>", content)
    dataCleaning(data3, "2")
    data4 = re.findall(r"<[a-z :]*endEvent[A-Z a-z \" = _ 0-9 \s < > * \-  # ^ : \/]*<\/[a-z :]*endEvent>", content)
    dataCleaning(data4, "3")
    # print(mapping)

def getSequence(content):
    global graph_matrix
    data = re.findall(r"<[a-z :]*sequenceFlow[a-z A-Z 0-9 \" \- = \s _]*\/>", content)
    for item in data:
        source = ""
        target = ""

        #Extracting Source Name 
        sourcetemp = re.findall(r"sourceRef=\"[A-Z a-z _ 0-9 \-]*\"", item)
        for sourcetemp1 in sourcetemp:
            sourcetemp2 = re.findall(r"\"[A-Z a-z 0-9 _ \-]*\"", sourcetemp1)
            for sourcetemp3 in sourcetemp2:
                source = sourcetemp3.strip('"')

        #Extracting Target Name
        targettemp = re.findall(r"targetRef=\"[A-Z a-z _ 0-9 \-]*\"", item)
        for targettemp1 in targettemp:
            targettemp2 = re.findall(r"\"[A-Z a-z 0-9 _ \-]*\"", targettemp1)
            for targettemp3 in targettemp2:
                target = targettemp3.strip('"')

        # print("****************************************")
        # print(source)
        # print(target)
        # print("****************************************")
        
        x = 0
        y = 0
        if source in mapping:
            x = mapping[source]-1
            if target in mapping:
                y = mapping[target]-1
                graph_matrix[x][y] = 1
            else:
                temp = re.findall(r"<[a-z :]*sequenceFlow [a-z A-Z 0-9 _ \- \" =]*sourceRef=\""+target+"\"[a-z A-Z 0-9 _ \- \" =]*\/>", content)
                # print(temp)
                for item1 in temp:
                    intertemp = re.findall(r"targetRef=\"[A-Z a-z _ 0-9 \-]*\"", item1)
                    for intertemp1 in intertemp:
                        intertemp2 = re.findall(r"\"[A-Z a-z 0-9 _ \-]*\"", intertemp1)
                        # print(intertemp2)
                        for intertemp3 in intertemp2:
                            intertarget = intertemp3.strip('"')
                            if intertarget in mapping:
                                y = mapping[intertarget]-1
                                # print(x)
                                # print(y)
                                graph_matrix[x][y] = 1
                            else:
                                temp1 = re.findall(r"<[a-z :]*sequenceFlow [a-z A-Z 0-9 _ \- \" =]*sourceRef=\""+intertarget+"\"[a-z A-Z 0-9 _ \- \" =]*\/>", content)
                                for item2 in temp1:
                                    temp2 = re.findall(r"targetRef=\"[A-Z a-z _ 0-9 \-]*\"", item2)
                                    for item3 in temp2:
                                        temp3 = re.findall(r"\"[A-Z a-z 0-9 _ \-]*\"", item3)
                                        for item4 in temp3:
                                            temp4 = item4.strip('"')
                                            y = mapping[temp4]-1
                                            graph_matrix[x][y] = 1 
    
    data1 = re.findall(r"<[a-z :]*messageFlow[a-z A-Z 0-9 \" \- = \s _]*\/>", content)
    # print(data1)
    for item in data1:
        source = ""
        target = ""

        #Extracting Source Name 
        sourcetemp = re.findall(r"sourceRef=\"[A-Z a-z _ 0-9 \-]*\"", item)
        for sourcetemp1 in sourcetemp:
            sourcetemp2 = re.findall(r"\"[A-Z a-z 0-9 _ \-]*\"", sourcetemp1)
            for sourcetemp3 in sourcetemp2:
                source = sourcetemp3.strip('"')

        #Extracting Target Name
        targettemp = re.findall(r"targetRef=\"[A-Z a-z _ 0-9 \-]*\"", item)
        for targettemp1 in targettemp:
            targettemp2 = re.findall(r"\"[A-Z a-z 0-9 _ \-]*\"", targettemp1)
            for targettemp3 in targettemp2:
                target = targettemp3.strip('"')
        
        # print(str(source)+","+str(target))
        x = 0
        y = 0
        if source in mapping:
            x = mapping[source]-1
            if target in mapping:
                y = mapping[target]-1
                graph_matrix[x][y] = 1


def createCsv(file):
    global graph_matrix
    for x in range(count):
        for y in range(count):
            if(graph_matrix[x][y] == 1):
                # print(str(x+1)+","+str(y+1))
                file.write(str(x+1)+" "+str(y+1)+"\n")

def createGraph():
    # G = nx.DiGraph()
    G = nx.read_edgelist('final.csv',create_using=nx.DiGraph())
    print(nx.info(G))
    print(nx.is_directed(G))
    nx.draw(G ,with_labels=True)
    plt.show()

def createAdjGraph(g):
    global graph_matrix
    for i in range(count):
        for j in range(count):
            if(graph_matrix[i][j] == 1):
                g.addEdge(i, j)

def readlist():
    file1 = open("temp2", "r")
    global listOfPath
    for line in file1:
        mylist = ast.literal_eval(line)
        listOfPath.append(mylist)
    # print(listOfPath)

def lengthOfLargestpath():
    global listOfPath
    l = 0
    for i in range(len(listOfPath)):
        if(len(listOfPath[i]) > l):
            l = len(listOfPath[i])
    return l

def algo():
    # print("algo")
    global count
    curr = [1]
    # next = []
    result = [[1]]
    l = lengthOfLargestpath()
    no = len(listOfPath)
    # print(len())
    i = 1
    # print (l)
    next = [[], [], [], [], [], [], []]
    temp = []
    countOr = 1
    countAnd = 1
    countFlow = 1
    while( i < l):
        j = 0
        while(j < no):
            if i >= len(listOfPath[j]):
                c = len(listOfPath[j])-1
            else:
                c = i
            # for x in range(len(curr)):
            if listOfPath[j][c] not in temp:
                temp.append(listOfPath[j][c])
            if listOfPath[j][c]  not in next[listOfPath[j][c-1]-1]:
                next[listOfPath[j][c-1]-1].append(listOfPath[j][c])
            j = j+1
        print("***************")
        print(curr)
        print(next)
        print(temp)
        print("***************")

        t = []
        t1 = []
        t2 = []
        
        if len(curr) == 1:
            if len(next[curr[0]-1]) > 1:
                print("enter")
                result[0].append("t_or"+str(countOr))
                t.append("t_or"+str(countOr))
                for x in range(len(next[curr[0]-1])):
                    t.append(next[curr[0]-1][x])
                result.append(t)
                countOr = countOr + 1
                t = []
            else:
                if len(next[curr[0]-1]) == 1 and  next[curr[0]-1][0] != count:
                    print(count)
                    strr = "t_flow"+str(countFlow)
                    strr1 = "t_or"+str(countOr)
                    strr2 = "t_and"+str(countAnd)
                    # if result[0][-1] != strr :
                    tem = result[0][-1]
                    result[0].pop()
                    result[0].append("t_flow"+str(countFlow))
                    t.append("t_flow"+str(countFlow))
                    t.append(tem)
                    for x in range(len(next[curr[0]-1])):
                        t.append(next[curr[0]-1][x])
                    result.append(t)
                    countFlow = countFlow + 1
                    t = []
                else:
                    result[0].append(curr[0])
                    # result[0].append(next[curr[0]-1])
                # print(t)
                # print(result)
        else:
            curr.sort()
            temp.sort()
            if curr == temp:
                p = 0
                for x in range(len(result)):
                    if set(curr).issubset(set(result[x])):
                        p = x
                        result[x][0] = "t_and"+str(countAnd)
                        result[0][p] = "t_and"+str(countAnd)
                        countAnd = countAnd + 1
                        countOr = countOr - 1
                # print(result)
            else:
                for x in range(len(curr)):
                    t.append(next[curr[x]-1])
                print(t)
                for x in range(len(t)):
                    t[x].sort()
                if t[0] == t[1] and len(t[0]) != 1:
                    result[0].append("t_or"+str(countOr))
                    t1.append("t_or"+str(countOr))
                    for x in range(len(t[0])):
                        t1.append(t[0][x])
                    result.append(t1)
                    t1 = []
                    countOr = countOr + 1
                    # print(result)
                else:
                    if t[0] != t[1] and len(t[0]) != 1:
                        for x in range(len(curr)):
                            # print(t[x])
                            if len(t[x]) == 1 and t[x][0] != count:
                                for y in range(len(result)):
                                    if curr[x] in result[y]:
                                        # print(y)
                                        for z in range(len(result[y])):
                                            if curr[x] == result[y][z]:
                                                result[y][z] = "t_flow"+str(countFlow)
                                                t1.append("t_flow"+str(countFlow))
                                                t1.append(curr[x])
                                                t1.append(t[x][0])
                                                result.append(t1)
                                                countFlow = countFlow + 1
                                                # print(result)
        del curr[:]
        curr = temp.copy()
        # print(curr)
        del temp[:]
        for z in range(len(curr)):
            next[curr[z]-1].clear()
        i = i+1

    result[0].append(count)
    print(result)



def main():
    global count
    global listOfPath
    if( len(sys.argv) == 1):
        print("Enter filename !!")
        sys.exit()  
    else:
        filename =  sys.argv[1]
        file = open(filename, "r")
        file1 = open("temp", "w")
        creatingTempFile(file, file1)
        file1.close()
        file1 = open("temp", "r")
        content = file1.read()

        file2 = open("final.csv","w")

        #Extracting the task
        getTask(content)
        # print(mapping)

        #Declaring matrix
        global graph_matrix
        graph_matrix = np.zeros( (count, count) )

        #Getting the sequence
        getSequence(content)
        # print(graph_matrix)

        #Declaring No. of nodes in graph
        g = Graph(count)

        #Create Adj-Graph
        createAdjGraph(g)

        g.printAllPaths(0,6)

        # result()
        
        readlist()

        print(listOfPath)
        count = 7

        #Clearing unnessary path 
        val = input("Enter number path remove:")
        for i in range(int(val)):
            val1 = input("Enter path number to be removed:")
            del listOfPath[int(val1)]
            print(listOfPath) 
        # del listOfPath[7]
        # del listOfPath[6]
        # del listOfPath[3]
        # del listOfPath[2]

        # print(listOfPath)

        # The Actual Logic
        algo()

        #Creating Edgelist csv file
        # createCsv(file2)
        # file2.close()

        #Creating graph
        # createGraph()

        #Closing of file
        file.close()
        file1.close()

if __name__== "__main__":
    main()