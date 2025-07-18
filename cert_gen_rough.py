import subprocess, json
from pathlib import Path
from os import getcwd

class DN_Attributes:
    def __init__(self, **attrs):
        valid_attrs = ["CN", "O", "OU", "C", "ST", "L", "STREET", "UID"]
        for attr, val in attrs.items():
            if (attr in valid_attrs):
                setattr(self, attr, val)

    def string(self) -> str:
        ret_str = "\""

        for attr, val in locals().items():
            ret_str.append(f"/{attr}={val}")

        ret_str.append("\"")

        return ret_str
    
    def load(self, CA_name: str):
        self.C = CAs[CA_name]["dn_attrs"]["C"]
        self.ST = CAs[CA_name]["dn_attrs"]["ST"]
        self.L = CAs[CA_name]["dn_attrs"]["L"]
        self.O = CAs[CA_name]["dn_attrs"]["O"]
### TEMPLATE
# CAs = {
#     "CA": {
#         "root_cert": "path",
#         "root_key": "path",
#         "dn_attrs": {
#             "C": "company",
#             "ST": "state",
#             "L": "city",
#             "O": "org"
#         },
#         "issued_certs": {
#             "cert": {
#                 "cert": "path",
#                 "key": "key"
#             }
#         }
#     }
# }
with open("CA_info.json", "r", encoding="utf-8") as f:
    CAs = json.load(f)

path_cwd = Path(getcwd())
path = {
    "cwd": path_cwd,
    "certs": path_cwd / "certs",
    "crl": path_cwd / "crl",
    "private": path_cwd / "private",
    "config": path_cwd / "config",
    "export": path_cwd / "export"
}

#itterate and mkdir on all directories

def create_CA(CA_name: str,
              keylen: int = 4096,
              validity: int = 3650,
              key_out_name: Path = "ca.key",
              out_name: Path = "ca.pem",
              dn: DN_Attributes = DN_Attributes()):
    command = f"openssl req \
        -x509 \
        -nodes \
        -newkey rsa:{keylen} \
        -days {validity} \
        -sha256 \
        -keyout {path['private'] / key_out_name} \
        -out {path['certs'] / out_name} \
        -subj {DN_Attributes}"
    
    try:
        completed = subprocess.run(
            command,
            shell=True,
            executable='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            capture_output=True,
            text=True,
        )
    except subprocess.CompletedProcess as e:
        print(f"Failed with: {e.returncode}")
        print(f"Output: {completed}")

    CAs[CA_name]
    CAs[CA_name]["root_cert"] = path['certs'] / out_name
    CAs[CA_name]["root_key"] = path['private'] / key_out_name

    CAs[CA_name]["dn_attrs"]["C"] = dn.C
    CAs[CA_name]["dn_attrs"]["ST"] = dn.ST
    CAs[CA_name]["dn_attrs"]["L"] = dn.L
    CAs[CA_name]["dn_attrs"]["O"] = dn.O

    with open("CA_info.json", "w", encoding="utf-8") as f:
        json.dump(CAs, f, indent=2)

    return

def create_signed_cert(CA_name: str,
                       keylen: int = 4096,
                       validity: int = 365,
                       key_out_name: Path = "signed_cert.key",
                       out_name: Path = "signed_cert.pem",
                       dn: DN_Attributes = DN_Attributes(),
                       extfile: str = "basic.cnf"):
    dn.load(CA_name)

    command = f"openssl req \
        -newkey rsa:{keylen} \
        -nodes \
        -keyout {path['private'] / key_out_name} \
        -subj {dn} \
        | openssl x509 \
        -req \
        -CA {CAs[CA_name]["root_cert"]} \
        -CAkey {CAs[CA_name]["root_key"]} \
        -CAcreateserial \
        -days {validity} \
        -out {path['certs'] / out_name} \
        -extfile {path['config'] / extfile} \
        -extensions server_cert"
    
    try:
        completed = subprocess.run(
            command,
            shell=True,
            executable='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            capture_output=True,
            text=True,
        )
    except subprocess.CompletedProcess as e:
        print(f"Failed with: {e.returncode}")
        print(f"Output: {completed}")

    CAs[CA_name]["issued_certs"][dn.CN]["cert"] = path['certs'] / out_name
    CAs[CA_name]["issued_certs"][dn.CN]["key"] = path['private'] / key_out_name

    with open("CA_info.json", "w", encoding="utf-8") as f:
        json.dump(CAs, f, indent=2)

    return
def export_full_chain(CA_name: str, cert1: str, cert2: str, out_name: Path):
    command = f"Get-Content {CAs[CA_name]["issued_certs"][cert1]["path"]}, {CAs[CA_name]["issued_certs"][cert2]["path"]} ` | Set-Content {path['path_certs'] / out_name}"

    try:
        completed = subprocess.run(
            command,
            shell=True,
            executable='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            capture_output=True,
            text=True,
        )
    except subprocess.CompletedProcess as e:
        print(f"Failed with: {e.returncode}")
        print(f"Output: {completed}")
    
    CAs[CA_name]["issued_certs"][f"fc_{out_name}"]["cert"] = path['certs'] / out_name
    CAs[CA_name]["issued_certs"][f"fc_{out_name}"]["key"] = CAs[CA_name]["issued_certs"][cert1]["path"]

    return
def export_pkcs12_pfx(CA_name: str,
                      cert: str,
                      out_name: Path = "bundle.pfx",
                      password: str = "password"):
    command = f"openssl pkcs12 \
    -export \
    -out {path['export'] / out_name} \
    -inkey {CAs[CA_name]["issued_certs"][cert]["key"]} \
    -in {CAs[CA_name]["issued_certs"][cert]["cert"]} \
    -certfile {CAs[CA_name]["root_cert"]} \
    -passout pass:{password}"

    try:
        completed = subprocess.run(
            command,
            shell=True,
            executable='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            capture_output=True,
            text=True,
        )
    except subprocess.CompletedProcess as e:
        print(f"Failed with: {e.returncode}")
        print(f"Output: {completed}")
    
    return