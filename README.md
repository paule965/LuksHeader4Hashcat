# LuksHeader4Hashcat
rebuild a luksheader for hashcat


Syntax: python LuksHeader4Hashcat.py "LUKS.img"


______

-parse statusinformation about Luks

-parse statusinformation about Keyslots

-choice to select (only!) one Keyslot

-aktivates 0xdead Keyslots

-change the PayloadOffset if it is >4096 sectors and rebuild the luksheader with a max filesize 4096+1 sectors
