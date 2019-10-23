import argparse
parser = argparse.ArgumentParser(prog = "luksrku client", description = "Connects to a luksrku key server and unlocks local LUKS volumes.", add_help = False)
parser.add_argument("-p", "--port", metavar = "port", default = 23170, help = "Port that is used for both UDP and TCP communication. Defaults to %(default)d.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity. Can be specified multiple times.")
parser.add_argument("filename", metavar = "filename", help = "Exported database file to load TLS-PSKs and list of disks from.")
parser.add_argument("hostname", metavar = "hostname", nargs = "?", help = "When hostname is given, auto-searching for suitable servers is disabled and only a connection to the given hostname is attempted.")
