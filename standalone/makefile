PHONY: start
start:
	@mkdir -p output
	@gcc -o output/standalone standalone.c cJSON.c -lm
	@output/standalone ./myconfig.json