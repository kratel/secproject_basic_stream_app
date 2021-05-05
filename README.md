# secproject_basic_stream_app

**Developed with** Python 3.9

This project was created for the Applied Cryptography course at NYU. There are two simple server and client programs. The server streams their desktop to the client.

The server program also supports multiple clients.

_As of now this was done using purely TCP, so it won't be super performant compared to a UDP server._

To use the program please follow the setup steps [Ubuntu/Debian setup](#ubuntudebian-pre-setup) and [setting up venv](#setting-up-virtualenv)

## Mock PKI
For an initial set of tests a mock PKI server was created [here](./simple_pki). Creating a PKI was out of the scope for the project, so it was left here as a proof of concept. The current code has some commented code that interacts with the mock PKI, in case you wanted to see how we planned to use it.

## Basic app references
To create the basic app, this stack overflow answer was used as a base:
https://stackoverflow.com/a/63717263/15782022


# Installation
## Ubuntu/Debian pre-setup

```bash
sudo apt-get install scrot
```
For system python3
```bash
sudo apt-get install python3-tk python3-dev
```

_Note: for specific version of python3.x_
```bash
sudo apt-get install python3.x-tk python3.x-dev
```

## Setting up Virtualenv

There are some dependencies for this project. It's recommended you setup a virtual environment that uses a python 3.9 interpreter. You can then run the following `pip` command to install the dependencies:

```bash
pip install -r requirements_ubuntu.txt
```

## Setting up testing RSA keys

**The programs require RSA keys to work.** There are default paths set in the programs to look for keys in an `env` directory.
To create some RSA keys to test the program with simply run the included bash script that is at the top level of the repo.
This script simply creates the directories that the programs will look through, and then creates the RSA keys with `openssl`

```bash
./setup_dev_keys.sh
```

This will create the following folders and files in the repo.
```
Repository Root


| env/   (directory)
    |---keys/ (directory)
        |---client/ (directory)
        |      |---client_01/ (directory)
        |      |      | private-key.pem (file)
        |      |      | public-key.pem (file)
        |      |      
        |      |---client_02/ (directory)
        |             | private-key.pem (file)
        |             | public-key.pem (file)
        |
        |---server/ (directory)
                |---trusted_keys/ (directory)
                |     | client_01-public-key.pem (file)
                |
                | private-key.pem (file)
                | public-key.pem (file)
```

_The `env/keys/server/trusted_keys/client_01-public-key.pem` file is just a copy of the `env/keys/client/client_01/public-key.pem` file_

# Usage

Each program can be run with just the default values. It may be helpful to set the logging level to debug with the flag `-l debug` in order to see a detailed activity log.

## Help and default arguments

Both programs accept command line arguments, to see what they are simply run the program with the `-h` flag. There are defaults set already to make simple testing on a local network easier.

```bash
python streaming_secured_server.py -h
python streaming_secured_client.py -h
```

## Running the programs

To run the programs you can simply call them from the top level of the repo with no extra arguments. Their default values are setup so they can work that way.

First start the server in one terminal
```bash
python streaming_secured_server.py
```

Then start the client in another terminal
```bash
python streaming_secured_client.py
```

To test multiple clients, simply start the client program multiple times in their own terminal sessions.

## Exiting the program

To exit the server press `ctrl` + `C` in the terminal to start the shutdown process.

_Shutting down the server, will also cause the client programs to terminate_

For the client you can just press the `Enter` key in the terminal to start the shutdown process.

## Testing Restricted Mode

To test restricted mode simple run the server with the restricted flag set to true.

Command to run restricted server with debug logging
```bash
python streaming_secured_server.py -l debug --restricted true
```

The default client arguments will allow a client to connect since they will use the RSA keys in `env/keys/client/client_01` directory which are whitelisted.
```bash
python streaming_secured_client.py -l debug
```

To test that keys not on the whitelist will **NOT** work you must specify the keys in the `env/keys/client/client_02` directory which are not whitelisted.
```bash
python streaming_secured_client.py -l debug --rsa-pub-key env/keys/client/client_02/public-key.pem --rsa-priv-key env/keys/client/client_02/private-key.pem
```
