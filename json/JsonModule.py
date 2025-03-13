import json
import dateutil.parser

# Utility functions to handle various data types
def from_datetime(x):
    return dateutil.parser.parse(x) if x else None

def from_none(x):
    return None

def from_str(x):
    return x if isinstance(x, str) else None

def from_int(x):
    return x if isinstance(x, int) and not isinstance(x, bool) else None

def from_bool(x):
    return x if isinstance(x, bool) else None

def from_list(f, x):
    assert isinstance(x, list)
    return [f(y) for y in x]

def to_class(c, x):
    assert isinstance(x, c)
    return x.to_dict()

# Network Connection Class
class NetworkConnection:
    def __init__(self, created, foreign_addr, foreign_port, local_addr, local_port, offset, owner, pid, proto, state):
        self.created = from_datetime(created)
        self.foreign_addr = from_str(foreign_addr)
        self.foreign_port = from_int(foreign_port)
        self.local_addr = from_str(local_addr)
        self.local_port = from_int(local_port)
        self.offset = from_int(offset)
        self.owner = from_str(owner)
        self.pid = from_int(pid)
        self.proto = from_str(proto)
        self.state = from_str(state)

    @staticmethod
    def from_dict(obj):
        return NetworkConnection(
            created=obj.get("Created"),
            foreign_addr=obj.get("ForeignAddr"),
            foreign_port=obj.get("ForeignPort"),
            local_addr=obj.get("LocalAddr"),
            local_port=obj.get("LocalPort"),
            offset=obj.get("Offset"),
            owner=obj.get("Owner"),
            pid=obj.get("PID"),
            proto=obj.get("Proto"),
            state=obj.get("State")
        )

# Function to parse NetworkConnection JSON
def parse_connection_json(json_string):
    data = json.loads(json_string)
    return [NetworkConnection.from_dict(item) for item in data]


# Class representing an LDR module
class LdrModule:
    def __init__(self, Pid, MappedPath, Base, InInit, InLoad, InMem, Process):
        self.Pid = Pid
        self.MappedPath = MappedPath
        self.Base = Base
        self.InInit = InInit
        self.InLoad = InLoad
        self.InMem = InMem
        self.Process = Process

    @classmethod
    def from_dict(cls, data):
        return cls(
            Pid=data.get("Pid"),
            MappedPath=data.get("MappedPath"),
            Base=data.get("Base"),
            InInit=data.get("InInit"),
            InLoad=data.get("InLoad"),
            InMem=data.get("InMem"),
            Process=data.get("Process")
        )
# Function to parse LDRModule JSON
def parse_module_json(json_string):
    data = json.loads(json_string)
    return [LdrModule.from_dict(item) for item in data]

# Namespace for memory forensic objects
class MemoryForensicsNamespace:
    """Namespace to contain the ProcessTree class."""

    class ProcessTree:
        def __init__(self, audit, cmd, create_time, exit_time, handles, image_file_name, offset_v, pid, ppid, path, session_id, threads, wow64, children):
            self.audit = audit
            self.cmd = cmd
            self.create_time = create_time
            self.exit_time = exit_time
            self.handles = handles
            self.image_file_name = image_file_name
            self.offset_v = offset_v
            self.pid = pid
            self.ppid = ppid
            self.path = path
            self.session_id = session_id
            self.threads = threads
            self.wow64 = wow64
            self.children = children

        @staticmethod
        def from_dict(obj):
            """
            Recursively creates a ProcessTree instance from a dictionary, handling nested children.
            """
            assert isinstance(obj, dict)
            audit = from_str(obj.get("Audit"))
            cmd = from_str(obj.get("Cmd"))
            create_time = from_datetime(obj.get("CreateTime"))
            exit_time = from_datetime(obj.get("ExitTime"))
            handles = from_none(obj.get("Handles"))
            image_file_name = from_str(obj.get("ImageFileName"))
            offset_v = from_int(obj.get("Offset(V)"))
            pid = from_int(obj.get("PID"))
            ppid = from_int(obj.get("PPID"))
            path = from_str(obj.get("Path"))
            session_id = from_int(obj.get("SessionId"))
            threads = from_int(obj.get("Threads"))
            wow64 = from_bool(obj.get("Wow64"))
            
            # Recursively parse children
            children = [MemoryForensicsNamespace.ProcessTree.from_dict(child) for child in obj.get("__children", [])]
            
            return MemoryForensicsNamespace.ProcessTree(audit, cmd, create_time, exit_time, handles, image_file_name, offset_v, pid, ppid, path, session_id, threads, wow64, children)

        def to_dict(self):
            """
            Recursively converts the ProcessTree instance into a dictionary, handling nested children.
            """
            result = {
                "Audit": from_str(self.audit),
                "Cmd": from_str(self.cmd),
                "CreateTime": self.create_time.isoformat() if self.create_time else None,
                "ExitTime": self.exit_time.isoformat() if self.exit_time else None,
                "Handles": from_none(self.handles),
                "ImageFileName": from_str(self.image_file_name),
                "Offset(V)": from_int(self.offset_v),
                "PID": from_int(self.pid),
                "PPID": from_int(self.ppid),
                "Path": from_str(self.path),
                "SessionId": from_int(self.session_id),
                "Threads": from_int(self.threads),
                "Wow64": from_bool(self.wow64),
                "__children": [child.to_dict() for child in self.children]  # Recursively convert children to dicts
            }
            return result

# Function to parse list of ProcessTree entries
def parse_audit_entry_list(json_string):
    """Parses a JSON string that contains a list of ProcessTree objects."""
    data = json.loads(json_string)
    
    process_list = [MemoryForensicsNamespace.ProcessTree.from_dict(item) for item in data]
    return process_list

def parse_ProcessTree_json(data):
    return [MemoryForensicsNamespace.ProcessTree.from_dict(item) for item in data]
    
def get_process_dictionary(process_list):
    """
    Converts a list of ProcessTree objects into a dictionary keyed by PID.
    Each child process is stored as a separate entry in the dictionary.
    """
    process_dict = {}

    def flatten_process(process):
        """
        Recursively flattens the process tree and adds entries to process_dict.
        """
        # Convert the current process to a dictionary without its children
        process_dict[process.pid] = {
            "Audit": process.audit,
            "Cmd": process.cmd,
            "CreateTime": process.create_time.isoformat() if process.create_time else None,
            "ExitTime": process.exit_time.isoformat() if process.exit_time else None,
            "Handles": process.handles,
            "ImageFileName": process.image_file_name,
            "Offset(V)": process.offset_v,
            "PID": process.pid,
            "PPID": process.ppid,
            "Path": process.path,
            "SessionId": process.session_id,
            "Threads": process.threads,
            "Wow64": process.wow64,
            "__children": []  # Children are handled separately
        }

        # Process children recursively
        for child in process.children:
            flatten_process(child)

    # Flatten all root-level processes
    for process in process_list:
        flatten_process(process)

    return process_dict