import os
import counterfit
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--targets', help="Path to targets folder", default="./targets")
    parser.add_argument("-c", "--config")
    parser.add_argument("-d", "--debug", help="run counterfit with debug enabled")
    args = parser.parse_args()

    
    print(counterfit.__version__)

    
    