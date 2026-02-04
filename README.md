##############################################################################################################################################
##############################################################################################################################################
<img width="794" height="318" alt="blocklists" src="https://github.com/user-attachments/assets/d2a82661-4a75-4e47-af11-aadc48336ea2" />
#### https://github.com/ckcameron/python-blocklists

#
# Copyright 2025, CK Cameron (chase@ckcameron.net), Shared under the Gnu General Public License, version 3.0 ONLY.
# Written in Python 3.14, using libraries re, http.clioent, traceback, pathlib, socket, time, elevate, 
# URLExtract, ssl, subprocess, cmd, argparsei, tempfile, multiprocessing, and ipaddress.
#
# This program will parse a list of files and directories, to scrape each line for ipaddresses, 
#     and domain names. Domain names will be looked-up for associated IPs. IPs and domains will 
#     be written to their respective files, and finally optimized by sorting, removing duplicate 
#     entries, and condensing the list of IPs into as few IP ranges as possible. If selected, the
#     script will also create an ipset blocklist and add rules to your iptables firewall
#     (the default rule is drop).
#
# This program is distributed WITHOUT ANY WARRANTY; this includes it being without the implied warrant of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.###### Feel free to contribute by putting in a  pull request if you are so inclined.

###### ckcameron on Discord
###############################################################################################################################################
