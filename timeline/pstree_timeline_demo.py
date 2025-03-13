import argparse
from TimeLineAnalysis import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare consecutive JSON files for processes.")
    parser.add_argument('-files', '--file_list', help="Comma-separated list of JSON files for comparison.")
    args = parser.parse_args()

    file_list = [file.strip() for file in args.file_list.split(',')]
    analysisObject = ProcessTimeLineAnalysis(file_list)
    analysisObject.compare_files()
