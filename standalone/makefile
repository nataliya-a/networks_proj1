PHONY: start
start:
	@mkdir -p output
	@gcc -o output/standalone standalone.c cJSON.c -lm -lpthread
	@output/standalone ./myconfig.json