## Server README

The timeout for the server to wait for a low entropy packet is 2 seconds.
The timeout for the server to wait for a high entropy packet is 5 seconds.

This is to prevent the server from waiting indefinitely for the packets. These numbers of seconds were chosen by arbitrarily.

The server also waits for 6 seconds before receiving the high entropy packets. This is to make sure that the server doesn't start listening and quit due to timeout while the client is sleeping for inter measurement time.

The server sometimes might not be able to connect to the client in the post probing phase, in that case, please run the program again.
In rare cases, the server might send incorrect verdict to the client, this happens because the server timeouts listening for packets before client sends them. In that case, please re-run the program again.

Then the server calculates if there was compression or not and sends the verdict to the client during the post probing phase and then the program terminates.

