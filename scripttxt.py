import csv

row =[]
mydict=[]
details=[]
vulnodes=[]

file1=open("AttackGraph.txt","r")
for line in file1:
    if(line[0].isdigit()):
        a=line.split(',')
        if(a[1].isdigit()):
            row1=[a[0],a[1]]
            row.append(row1)
        else:
            row2=[a[0],a[1]]
            details.append(row2)


for i in details:
   
    if(i[1].startswith ('vul',1,4)):
        vulnodes.append(i[0])
            
myFile= open("relations.csv","w")
with myFile:
    writer=csv.writer(myFile)
    writer.writerow(["Child","Parent"])
    writer.writerows(row)


print("The vul nodes are")
print(vulnodes)           

file1.close()
