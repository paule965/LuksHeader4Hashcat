# LuksHeader4Hashcat
rebuilds a luksheader for hashcat

Syntax: python LuksHeader4Hashcat.py "LUKS.img"

-parsing statusinformation about Luks

-parsing statusinformation about Keyslots

-allows selection of (only!) one Keyslot

-activates 0xdead Keyslots with (valid?) entrys

-changes the PayloadOffset if it is >4096 sectors and rebuild the luksheader with a max filesize 4096+1 sectors
