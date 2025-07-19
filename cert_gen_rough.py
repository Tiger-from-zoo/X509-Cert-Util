import subprocess, json
from pathlib import Path
from os import getcwd

from tkinter import Tk, Toplevel, Button, Label, Entry, Listbox, messagebox

CA_DN_FIELDS = 6
REQ_CA_DN_FIELDS = 2
DN_FIELDS = 4

FIELDS_DN_SPACE = 2

CA_ATTRS = ["* Common Name (CN): ", "* Organization (O): ", "* Country (C): ", "State (ST): ", "Locality (L): ", "UID: "]
ATTRS = ["* Common Name (CN): ", "State (ST): ", "Locality (L): ", "UID: "]
CA_ATTRS_SHORT = ["CN", "O", "C", "ST", "L", "UID"]
ATTRS_SHORT = ["CN", "ST", "L", "UID"]

CA_VAR_LIST = ["CA_name", "keylen", "validity", "key_out_name", "out_name"]

class DN_Attributes:
    def __init__(self, **attrs):
        for attr, val in attrs.items():
            if (attr in CA_ATTRS_SHORT):
                setattr(self, attr, val)

    def string(self) -> str:
        ret_str = "\""

        for attr, val in self.__dict__.items():
            ret_str += (f"/{attr}={val}")

        ret_str += ("\"")

        return ret_str
    
    def load(self, CA_name: str):
        self.O = CAs[CA_name]["dn_attrs"]["O"]
        self.C = CAs[CA_name]["dn_attrs"]["C"]

    def set(self, var: str, val: str ):
        setattr(self, var, val)
        return

class Cert_Input:
    def __init__(self):
        self.CA_name: str | None = None
        self.keylen: int = 4096
        self.validity: int = 365
        self.key_out_name: str | None = None
        self.out_name: str | None = None
        self.dn: DN_Attributes
        self.ext_file: str = "basic.cnf"
        self.cert1: str | None = None
        self.cert2: str | None = None
        self.password: str = "password"

    def set(self, var: str, val: str | int | DN_Attributes):
        setattr(self, var, val)
        return

### TEMPLATE
# CAs = {
    # "CA": {
        # "root_cert": "path",
        # "root_key": "path",
        # "dn_attrs": {
            # "O": "org",
            # "C": "country"
        # },
        # "issued_certs": {
            # "cert": {
                # "cert": "path",
                # "key": "key"
            # }
        # }
    # }
# }
CAs = {}

path_cwd = Path(getcwd())
path = {
    "cwd": path_cwd,
    "certs": path_cwd / "certs",
    "crl": path_cwd / "crl",
    "private": path_cwd / "private",
    "config": path_cwd / "config",
    "export": path_cwd / "export"
}
json_path = path_cwd / "CA_info.json"
json_path.touch(exist_ok=True)

for direc in path.values():
    direc.mkdir(parents=True, exist_ok=True)

def create_CA(details: Cert_Input):
    if (details.CA_name in CAs):
        outx = messagebox.askokcancel("Warning", f"CA: \"{details.CA_name}\" already exists. Overwrite?", parent=create_CA_window)
        if (outx is False):
            return subprocess.CompletedProcess([], 2)
        else:
            pass
    
    command = f"openssl req -x509 \
        -nodes \
        -newkey rsa:{details.keylen} \
        -days {details.validity} \
        -sha256 -keyout \"{path['private'] / details.key_out_name}\" \
        -out \"{path['certs'] / details.out_name}\" \
        -subj {details.dn.string()}"
    
    completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
        )

    if (completed.returncode == 0):
        CAs[details.CA_name] = {}

        CAs[details.CA_name]["root_cert"] = str(path['certs'] / details.out_name)
        CAs[details.CA_name]["root_key"] = str(path['private'] / details.key_out_name)

        CAs[details.CA_name]["dn_attrs"] = {}
        CAs[details.CA_name]["issued_certs"] = {}

        CAs[details.CA_name]["dn_attrs"]["O"] = details.dn.O
        CAs[details.CA_name]["dn_attrs"]["C"] = details.dn.C

        json_path.touch(exist_ok=True)
        with open(json_path, "w+", encoding="utf-8") as f:
            json.dump(CAs, f, indent=2)

    return completed

def create_signed_cert(details: Cert_Input):
    details.dn.load(details.CA_name)

    command = f"openssl req \
        -newkey rsa:{details.keylen} \
        -nodes \
        -keyout {path['private'] / details.key_out_name} \
        -subj {details.dn.string()} \
        | openssl x509 \
        -req \
        -CA {CAs[details.CA_name]["root_cert"]} \
        -CAkey {CAs[details.CA_name]["root_key"]} \
        -CAcreateserial \
        -days {details.validity} \
        -out {path['certs'] / details.out_name} \
        -extfile {path['config'] / details.ext_file} \
        -extensions server_cert"
    
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
        )
    except subprocess.CompletedProcess as e:
        print(f"Failed with: {e.returncode}")
        print(f"Output: {completed}")

    CAs[details.CA_name]["issued_certs"][details.dn.CN] = {}

    CAs[details.CA_name]["issued_certs"][details.dn.CN]["cert"] = str(path['certs'] / details.out_name)
    CAs[details.CA_name]["issued_certs"][details.dn.CN]["key"] = str(path['private'] / details.key_out_name)

    json_path.touch(exist_ok=True)
    with open(json_path, "w+", encoding="utf-8") as f:
        json.dump(CAs, f, indent=2)

    return
def export_full_chain(details: Cert_Input):
    command = f"Get-Content {CAs[details.CA_name]["issued_certs"][details.cert1]["path"]}, {CAs[details.CA_name]["issued_certs"][details.cert2]["path"]} ` | Set-Content {path['path_certs'] / details.out_name}"

    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
        )
    except subprocess.CompletedProcess as e:
        print(f"Failed with: {e.returncode}")
        print(f"Output: {completed}")
    
    CAs[details.CA_name]["issued_certs"][details.dn.CN] = {}

    CAs[details.CA_name]["issued_certs"][f"fc_{details.out_name}"]["cert"] = str(path['certs'] / details.out_name)
    CAs[details.CA_name]["issued_certs"][f"fc_{details.out_name}"]["key"] = CAs[details.CA_name]["issued_certs"][details.cert1]["path"]

    json_path.touch(exist_ok=True)
    with open(json_path, "w+", encoding="utf-8") as f:
        json.dump(CAs, f, indent=2)

    return
def export_pkcs12_pfx(details: Cert_Input):
    command = f"openssl pkcs12 \
    -export \
    -out {path['export'] / details.out_name} \
    -inkey {CAs[details.CA_name]["issued_certs"][details.cert1]["key"]} \
    -in {CAs[details.CA_name]["issued_certs"][details.cert1]["cert"]} \
    -certfile {CAs[details.CA_name]["root_cert"]} \
    -passout pass:{details.password}"

    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
        )
    except subprocess.CompletedProcess as e:
        print(f"Failed with: {e.returncode}")
        print(f"Output: {completed}")
    
    return

# GUI
def create_entry_label_grid(window: Toplevel, fields: list, naming: str, start_idx: int = 0):
    final_idx: int
    for idx, field in enumerate(fields):
        globals()[f"{naming}_L_{idx}"] = Label(window, text=field)
        globals()[f"{naming}_E_{idx}"] = Entry(window)
        globals()[f"{naming}_L_{idx}"].grid(row=(idx + start_idx), column=1, pady=3)
        globals()[f"{naming}_E_{idx}"].grid(row=(idx + start_idx), column=2, pady=3)
        final_idx = idx

    return (final_idx + 1)

def create_dn_grid(window: Toplevel, CA: bool, naming: str, idx: int):
    Label(window, text="Distinguished Name Attributes: ").grid(row=(idx + 1), column=1, columnspan=2, sticky="")
    if (CA == True):
        create_entry_label_grid(window, CA_ATTRS, f"{naming}_DN", (idx + 2))
    elif (CA == False):
        create_entry_label_grid(window, ATTRS, f"{naming}_DN", (idx + 2))
        

def CA_window_wrapper(fields_end_idx: int, fields: list, dn_fields: list):
    errs = []
    dn_errs = []
    filled_fields = []

    details = Cert_Input()
    dn_details = DN_Attributes()
    for i in range(fields_end_idx):
        if (globals()[f"CA_w_E_{i}"].get() != ""):
            details.set(CA_VAR_LIST[i], globals()[f"CA_w_E_{i}"].get())
            globals()[f"CA_w_L_{i}"].config(fg="black")
        else:
            errs.append(i)

    for i in range(REQ_CA_DN_FIELDS):
        if (globals()[f"CA_w_DN_E_{i}"].get() != ""):
            globals()[f"CA_w_DN_L_{i}"].config(fg="black")
        else:
            dn_errs.append(i)

    if ((len(errs) != 0) or (len(dn_errs) != 0)):
        for err in errs:
            globals()[f"CA_w_L_{err}"].config(fg="red")

        for dn_err in dn_errs:
            globals()[f"CA_w_DN_L_{dn_err}"].config(fg="red")
        return

    for i in range(CA_DN_FIELDS):
        if (globals()[f"CA_w_DN_E_{i}"].get() != ""):
            filled_fields.append(i)
    for filled in filled_fields:
        dn_details.set(CA_ATTRS_SHORT[filled], globals()[f"CA_w_DN_E_{filled}"].get())

    details.dn = dn_details
    create_CA_ret = create_CA(details)
    if(create_CA_ret.returncode == 0):
        for i in range(fields_end_idx):
            globals()[f"CA_w_E_{i}"].delete(0, "end")
        
        for i in range(CA_DN_FIELDS):
            globals()[f"CA_w_DN_E_{i}"].delete(0, "end")
    elif (create_CA_ret.returncode == 1):
        messagebox.showerror("Error: 1", create_CA_ret.stdout)
def create_CA_window_button(*args, **kwargs):
    global create_CA_window
    create_CA_window = Toplevel(root)
    create_CA_window.geometry("400x400")
    create_CA_window.title("Create CA")


    for i in range(4):
        create_CA_window.grid_columnconfigure(i, weight=1)

    ca_dn_row = create_entry_label_grid(create_CA_window, [
    "* CA Name: ",
    "* Key length (bits): ",
    "* Validity (days): ",
    "* Key file name: ",
    "* Certificate file name: "], "CA_w")
    ca_button_row = create_dn_grid(create_CA_window, True, "CA_w", ca_dn_row)

    globals()[f"CA_w_E_{CA_VAR_LIST.index("keylen")}"].insert(0, "4096")
    globals()[f"CA_w_E_{CA_VAR_LIST.index("validity")}"].insert(0, "3650")
    globals()[f"CA_w_E_{CA_VAR_LIST.index("key_out_name")}"].insert(0, "priv.key")
    globals()[f"CA_w_E_{CA_VAR_LIST.index("out_name")}"].insert(0, "root.crt")

    Button(create_CA_window, text="Create", command=lambda: CA_window_wrapper(ca_dn_row, [], [])).grid(row=ca_button_row, column=1, columnspan=2)


def create_signed_cert_button(*args, **kwargs):
    create_signed_cert = Toplevel(root)
    create_signed_cert.geometry("400x400")
    create_signed_cert.title("Create Signed Certificate")

def export_fullchain_button(*args, **kwargs):
    export_fullchain = Toplevel(root)
    export_fullchain.geometry("400x400")
    export_fullchain.title("Export Fullchain/Concatenate")

def export_export_pkcs12_pfx_button(*args, **kwargs):
    export_export_pkcs12_pfx = Toplevel(root)
    export_export_pkcs12_pfx.geometry("400x400")
    export_export_pkcs12_pfx.title("Export as PKCS#12/PFX")

def load_json(*args, **kwargs):
    global CAs
    with open(json_path, "r+", encoding="utf-8") as f:
        CAs = json.load(f)

root = Tk()
root.title("X509 Cert Util")
root.geometry("400x400")

create_CA_button = Button(root, text="Create Certificate Authority(CA)", command=create_CA_window_button).pack()
create_signed_cert_button = Button(root, text="Create Signed Certificate", command=create_signed_cert_button).pack()
export_fullchain_button = Button(root, text="Export Fullchain/Concatenate ", command=export_fullchain_button).pack()
export_export_pkcs12_pfx = Button(root, text="Export as PKCS#12/PFX", command=export_export_pkcs12_pfx_button).pack()
load_json_button = Button(root, text="Load JSON Configuration", command=load_json).pack()

root.mainloop()