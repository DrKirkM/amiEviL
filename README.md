# amiEviL

![banner](/figures/Banner.jpg)

This script is intended to check if the hash of suspicious file is in the Virus Total database.

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

