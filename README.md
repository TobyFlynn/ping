# Ping

The source and Makefile are contained in the **src** directory. To make the project, enter the **src** directory and enter the command **make**.

The resulting binary will be in the **build** directory and this needs to be run as a sudo user in order to work. The command to run the program is **./ping [hostname or IP address] [options]**.

For example: **./ping www.google.co.uk -t 64** which will ping google using a TTL value of 64 until the progam is ended using CTRL+C.
