PHONY: start
start:
	@mkdir -p output
	@gcc -o output/server server.c cJSON.c -lm
	@output/server ./myconfig.json

