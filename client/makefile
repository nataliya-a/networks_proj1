PHONY: start
start:
	@mkdir -p output
	@gcc -o output/client client.c cJSON.c -lm
	@output/client myconfig.json