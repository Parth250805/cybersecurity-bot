import os
import sys
import io
import portalocker

class PidFileLock:
    def __init__(self, filename):
        self.filename = filename
        self.fd = None
        
    def acquire(self):
        try:
            self.fd = open(self.filename, 'w')
            portalocker.lock(self.fd, portalocker.LOCK_EX | portalocker.LOCK_NB)
            self.fd.write(str(os.getpid()))
            self.fd.flush()
            return True
        except (portalocker.LockException, IOError):
            if self.fd:
                self.fd.close()
                self.fd = None
            return False
            
    def release(self):
        if self.fd:
            try:
                portalocker.unlock(self.fd)
                self.fd.close()
                self.fd = None
                os.unlink(self.filename)
            except (portalocker.LockException, IOError):
                pass