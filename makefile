all:
	gcc -lssl -o server_side server_side.c
	gcc -lssl -o netcat_part netcat_part.c
