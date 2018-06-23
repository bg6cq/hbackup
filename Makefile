hbackup_server: hbackup_server.c
	gcc -o hbackup_server -g -Wall hbackup_server.c -lcrypto

indent: hbackup_server.c
	indent  hbackup_server.c -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
		-cli0 -d0 -di1 -nfc1 -i8 -ip0 -l100 -lp -npcs -nprs -npsl -sai \
		-saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
indentpython:
	yapf -i hbackup.py hbackup_check_hashedfile.py
