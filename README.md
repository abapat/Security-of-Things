# Security-of-Things
A python implementation of secure communication channel between an Internet of Things (Intel Galileo) and a computer.

-The purpose of this implementation is present a light, barebones way to ensure secure communication between a client
machine and IOT devices

In order to run the code:

Please install the pycrypto library and set up mongodb 

Dependency Instructions for Linux/Unix:

- If you do not have python dev tools installed run the following command:

	$ sudo apt-get install python-dev

- If you do not have pip installed run the following command:
	
	$ sudo apt-get install python-pip

- If you have all the above installed, run the following command in terminal:

	$ sudo pip install pycrypto
        $ sudo pip install pymongo
TO RUN THE CODE:

- Run the following command to generate appropriate RSA keys 
  NOTE: There are already keys included for testing in this repo

	$ python generateKeys.py

- Run the following command to set up a username and password for the IOT
  NOTE: There is already a dummy user in this repo

	$ python hash.py

- Run the following command to run the client side code:

	$ python client.py

- Run the follwing command after running client.py on the IOT device

	$ python IOT.py

THANK YOU FOR YOUR TIME!
