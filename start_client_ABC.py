import os
import socket
import subprocess


if __name__ == "__main__":
    # print(server_file)

    client_file = os.path.join(os.getcwd(), "chat_client.py")
    subprocess.Popen(r"python3 " + client_file + " --port 5005 --client A", shell=True)
    subprocess.Popen(r"python3 " + client_file + " --port 5005 --client B", shell=True)
    subprocess.Popen(r"python3 " + client_file + " --port 5005 --client C", shell=True)
