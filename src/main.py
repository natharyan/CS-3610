import keys
import subroutines
from OpenSSL import crypto, SSL
import socket
import threading
import time
import os

import subroutines.certificate # user defined module
import subroutines.encryptionschemes # user defined module
import tasks # user defined module

if __name__ == "__main__":
    tasks.task1()
    tasks.task2()
    tasks.task3()
    tasks.task4()
    tasks.task5()
    tasks.task6()
