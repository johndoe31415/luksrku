import argparse
parser = argparse.ArgumentParser(prog = "luksrku edit", description = "", add_help = False)
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity. Can be specified multiple times.")
parser.add_argument("filename", metavar = "filename", nargs = "?", type = str, help = "Database file to edit.")
