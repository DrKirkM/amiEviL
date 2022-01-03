# amiEviL

![banner](/figures/Banner.JPG)

This program uses the Virus Total API to determine if your suspicious file is malicious or not. The program requests the hash (MD5, SHA-1, SHA-256) of a file and outputs information (if any) from the Virus Total database. Currently, this version will output: the file type, names seen in the wild, the number of security vendors that have flagged it as malicious, undetected, and unable to process the file.


You will need an api key from Virus Total to use this script. 

https://www.virustotal.com 

https://developers.virustotal.com/reference/overview

* In the script amiEviL.py you must edit here:
``` python 
################### API KEY MUST GO BELOW #############################
headers = {                                                           #
    "Accept": "application/json",                                     #
    "x-apikey": "API KEY GOES HERE"   #Api-Key Goes Here.             # 
}                                                                     #
#######################################################################
```
**Dependencies:**
* requests

These can be installed via PIP or with your favorite package manager.
Example of installing all dependencies using pip:
```python
pip install -r requirements.txt
```
**Example**
![](/figures/example.JPG)
![](/figures/example2.JPG)
![](/figures/example3.JPG)
