import sys
from email import policy
from email.parser import BytesParser

# Sending Email Address
# Subject Line
# Recipient Email Addresses
# Sending Server IP & Reverse DNS
# Reply-to Address
# Date & Time

def search(file_name):
    try:
        with open(file_name, 'rb') as fp:
            msg = BytesParser(policy=policy.default).parse(fp)

        artifacts_file = (''.join(f"{msg['subject']}.txt"))

        with open(artifacts_file, 'w') as f:
            f.write(f"From: {msg['from']}\n")
            f.write(f"Subject: {msg['subject']}\n")
            f.write(f"To: {msg['to']}\n")
            f.write(f"Sender IP: {msg['X-Sender-IP']}\n")
            f.write(f"Reply-To: {msg['Reply-To']}\n")
            f.write(f"Date: {msg['date']}\n\n")
            f.write(f"Perform a reverse DNS search with the Sender IP -> {msg['X-Sender-IP']}\n")
            f.write('Open the .eml using a text editor and search for files attached, hash them and investigate on VirusTotal if they are malicious.')
            print(f'[+] The file "{artifacts_file}" was created in this directory.')
    except FileNotFoundError:
        print("The file provided is not in this directory or does not exist.")

if __name__ == '__main__':
    try:
        file_name = sys.argv[1]
        if file_name.endswith(".eml"):
            print(file_name)
            search(file_name)
        else:
            print("Insert a .eml file")
    except IndexError:
        print('Insert the email name after the program call.\n#> python search_artifact.py <val>.eml')