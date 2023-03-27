## Server README

The timeout for the server to wait for a low entropy packet is 2 seconds.
The timeout for the server to wait for a high entropy packet is 5 seconds.

This is to prevent the server from waiting indefinitely for the packets. These numbers of seconds were chosen by arbitrarily.

The server also waits for 6 seconds before receiving the high entropy packets. This is to make sure that the server doesn't start listening and quit due to timeout while the client is sleeping for inter measurement time.

In case, the server shows 'Waiting for high entropy packets...' after client shows 'Sending high entropy udp packets now.', please run the program again as it is a rare case and results in incorrect verdict.

Then the server calculates if there was compression or not and sends the verdict to the client during the post probing phase and then the program terminates.

