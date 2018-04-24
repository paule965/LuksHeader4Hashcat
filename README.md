# LuksHeader4Hashcat
rebuild a luksheader for hashcat

Syntax: python LuksHeader4Hashcat.py "LuksHeader.img"

-parse statusinformation about Luks

-parse statusinformation about Keyslots

-give the choice to select (only!) one Keyslot

-aktivates Dead Keyslots

-change the PayloadOffset if it is >4096 sectors

-rebuild the luksheader with a max filesize 4096+1 sectors
