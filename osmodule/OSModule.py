import json
from abc import ABC, abstractmethod
""" Following statements are required to add current path to import modules"""
from inspect import getsourcefile
import os.path
import sys
current_path = os.path.abspath(getsourcefile(lambda:0))
current_dir = os.path.dirname(current_path)
sys.path.insert(0, current_dir + os.path.sep + "delta")
parent_dir = current_dir[:current_dir.rfind(os.path.sep)]
sys.path.insert(0, parent_dir + os.path.sep + "delta")
from delta.DeltaModule import MemoryDiff

class OSInterface(ABC):
    """
    Abstract base class to define an interface for interacting with an operating system.
    """
    def __init__(self, volatility_wrapper, output_handler):
        self.volatility_wrapper = volatility_wrapper
        self.output_handler = output_handler

    @abstractmethod
    def extractProcesses(self):
        """
        Runs the process retrieval mechanism from the memory dump.
        
        Returns:
            str: A json_string object representing the processes.
        """
        pass

    @abstractmethod
    def extractConnections(self):
        """
        Retrieves network connections from the memory dump.
        
        Returns:
            str: A json_string object representing the network connections.
        """
        pass

    @abstractmethod
    def extractModules(self):
        """
        Retrieves loaded modules from the memory dump.
        
        Returns:
            str: A json_string object representing the modules.
        """
        pass
        
    @abstractmethod
    def extractLibraries(self):
        """
        Retrieves loaded modules from the memory dump.
        
        Returns:
            str: A json_string object representing the libraries.
        """
        pass

    @abstractmethod
    def extractRegistries(self):
        """
        Retrieves registry data from the memory dump.
        
        Returns:
            str: A json_string object representing the registry data.
        """
        pass

    @abstractmethod
    def extractUsers(self):
        """
        Retrieves user information from the memory dump.
        
        Returns:
            str: A json_string object representing the users.
        """
        pass
        
    def executeAndSaveCommand(self, command, file):
        
        raw_output = self.volatility_wrapper.run_command(command)
        cleaned_output = self.output_handler.clean_json_output(raw_output)        
        data = json.loads(cleaned_output)           
        self.output_handler.write_json_output(file, data)
        return data


class WindowsInterface(OSInterface):
    """
    Concrete implementation of OSInterface for Windows-based systems.
    """
    
    def __init__(self, volatility_wrapper, output_handler):
        super().__init__(volatility_wrapper, output_handler)

    def extractProcesses(self):
        """
        Runs the process retrieval mechanism for the Windows memory dump.
        
        Returns:
            str: A json_string object representing the processes.
        """
        return self.executeAndSaveCommand('windows.pstree', 'pstree')

    def extractConnections(self):
        """
        Retrieves network connections from the Windows memory dump. This function executes netstat and netscan and takes a difference and adds netscan-netstat connections in netscan file. 
        
        Returns:
            str: A json_string object representing the network connections.
        """
        netstat = self.executeAndSaveCommand('windows.netstat', 'netstat_original')
        netscan = self.executeAndSaveCommand('windows.netscan', 'netscan')

        deltaObject = MemoryDiff()
        deltaObject.diffConnections(netstat, netscan)
        netstat = netstat + deltaObject.connection_updates['added']
        self.output_handler.write_json_output('netstat', netstat)

    def extractModules(self):
        """
        Retrieves loaded modules from the Windows memory dump.
        
        Returns:
            str: A json_string object representing the modules.
        """
        return self.executeAndSaveCommand('windows.ldrmodules', 'ldrmodules')
        
    def extractLibraries(self):
        """
        Retrieves loaded modules from the Windows memory dump.
        
        Returns:
            str: A json_string object representing the dlls.
        """
        return self.executeAndSaveCommand('windows.dlllist','dlllist')

    def extractRegistries(self):
        """
        Retrieves registry data from the Windows memory dump.
        
        Returns:
            str: A json_string object representing the registry data.
        """
        return self.executeAndSaveCommand('windows.registry.printkey', 'printkey')


    def extractUsers(self):
        """
        Retrieves user information from the Windows memory dump.
        
        Returns:
            str: A json_string object representing the users.
        """
        return self.executeAndSaveCommand('windows.hashdump', 'hashdump')
