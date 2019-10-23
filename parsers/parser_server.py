import argparse
parser = argparse.ArgumentParser(prog = "luksrku server", description = "Starts a luksrku key server.", add_help = False)
parser.add_argument("-p", "--port", metavar = "port", default = 23170, help = "Port that is used for both UDP and TCP communication. Defaults to %(default)d.")
parser.add_argument("-s", "--silent", action = "store_true", help = "Do not answer UDP queries for clients trying to find a key server, only serve key database using TCP.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity. Can be specified multiple times.")
parser.add_argument("filename", metavar = "filename", help = "Database file to load keys from.")
