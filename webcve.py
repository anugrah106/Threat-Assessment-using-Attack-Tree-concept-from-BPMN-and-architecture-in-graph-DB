import bs4
from urllib import urlopen as uReq
from bs4 import BeautifulSoup as soup
detial=input("Enter CVE ID :")
print(detial)
detial=detial.strip()
my_url="https://nvd.nist.gov/vuln/detail/"
my_url+=detial
print(my_url)
uClient=uReq(my_url)
page_html=uClient.read()

uClient.close()
page_soup=soup(page_html,"html.parser")
containers=page_soup.find("p",{"data-testid":"vuln-cvssv3-score-container"})
print("Base Score:",containers.span.text)
