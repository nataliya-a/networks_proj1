## Nataliya Karmarkar

# Part I: Server-Client

## Requirements

`make` is required to build the project.

## Build

To build and run the project, run the following command in the project directory:

```
cd server
make start
```

```
cd client
make start
```

If everything goes well, the final verdict will be printed to the client console.

## Result

The final verdict will be printed to the client console.

[NOTE: The server-client version usess 192.168.64.3 as the server IP address and 192.168.64.5 as the client IP address. If you want to change it, please change it in the server/myconfig.json file and client/myconfig.json file respectively.]

# Part I: Standalone

## Requirements

`make` is required to build the project.

## Build

To build and run the project, run the following command in the project directory:

```
cd standalone
sudo make start
```

If everything goes well, the final verdict will be printed to the console.

## Result

The final verdict will be printed to the console.

[NOTE: Sometimes the standalone version may not work properly. If that happens, please re-run it.]
[NOTE: The standalone version usess 192.168.64.3 as the server IP address. If you want to change it, please change it in the standalone/myconfig.json file.]
