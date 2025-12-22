#########################################################################################
#########################################################################################
![ alt text ](https://github.com/ckcameron/python-blocklists/blocklists.png?raw=true)
# https://github.com/ckcameron/python-blocklists
#
# Copyright 2025, CK Cameron (chase@ckcameron.net), Shared under the Gnu General Public License, version 3.0 ONLY
# Written in Python 3.13
# 
# Library dependencies: re, time, pathlib, ipaddress, and socket
# 
# This program will parse a list of files and directories, to scrape each line for ipaddresses, 
#     and domain names. Domain names will be looked up for associated IPs. IPs and domains will 
#     be written to their respective files, and finally optimized by sorting, removing duplicate 
#     entries, and condensing the list of IPs into as few IP ranges as possible.
# 
# Note: The script currently will pickup and use impossible IP addresses, 
#      e.g. 333.333.333.333. I have not run into problems with this as yet for my purposes,
#      although I may change it at a later date.
# 
# Feel free to contribute by putting in a  pull request if you are so inclined.
#
# ckcameron on Discord
########################################################################################