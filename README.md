# pcap-reader

Just a simple pcap reader for the terminal.

# Building

Dependency: `libfmt`

Run the following commands in the root directory of the project.

```
mkdir build
cd build
cmake ..
make
```
To install it, `sudo make install`.

# Usage

Running the binary without any arguments will provide the following output:
```
Required flags:
	-f <pcap> -- Specify the path to a pcap file to read.
Optional flags:
	-d <size> -- Sets the size of the rows when printing packet data.
	-n <index> -- Start from/print a specific packet at the given index.
	-i -- Open the reader in interactive mode.
	-h -- Don't print the pcap and packet headers.
	-r -- Print packet data in raw format.
```

Simply pass the required flag along with any optional flags.
