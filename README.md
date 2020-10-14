# ft_ping
Reimplementation of the ping program. Added an IP spoofing option.

## Installation
### Step 1 :
Clone the repository with `git clone --recurse-submodules https://github.com/AntoineFonck/ft_ping.git`
### Step 2 :
Go to the directory and compile the project --> `cd ft_ping/ && make`
### Step 3 :
Launch the program --> `sudo ./ft_ping -h`

## Functionalities
- Spoof the sender IP (option -S)
- Verbose output
- Ping flood
- Quiet output
- Send a specific number of packets
- Wait for a specific amount of time between each ping
- Fill ICMP data with a specific ASCII character
- Set the size of the ICMP data payload
- Set TTL 
- Set timeout for receiving echo replies
