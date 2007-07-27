"""
    Python server component for TTD Patch multiplayer
"""

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
import struct

# prefixed to all struct format strings
STRUCT_PREFIX = '!'

def hex (bytes) :
    return ' '.join(['%#04x' % ord(b) for b in bytes])
    
class NotEnoughDataError (Exception) : 
    pass

class Buffer (object) :
    # for mark/reset
    __position = None
    
    # the buffer
    buf = None
    
    def __init__ (self, str=None, rf=None, wf=None) :
        """
            Pass in a string to create a read-only buffer over that string.
            Pass in nothing to create a writeable buffer.
        """
        
        self.buf = None
        
        if str :
            self.buf = StringIO(str)
        else :
            self.buf = StringIO()
            
        self.read_pos = 0
        self.read_size = 0
    
    def read (self, size=None) :
        """
            Read and return up to the given amount of bytes, or all bytes
            available if no size given.
        """
        if size == 0 :
            raise ValueError("can't read zero bytes")
            
        if size :
            return self.buf.read(size)
        else :
            return self.buf.read()
    
    def readAll (self, size) :
        """
            Either returns size bytes of data, or raises a NotEnoughDataError
        """
        
        if size == 0 :
            raise ValueError("can't read zero bytes")
        
        pos = self.buf.tell()
        data = self.read(size)
        
        if len(data) < size :
            self.read_pos = pos
            self.read_len = len(data)
            raise NotEnoughDataError()
        else :
            return data
        
    def readStruct (self, fmt) :
        """
            Uses readAll to read struct data, and then unpacks it according to
            the given foramt. Always returns a tuple
        """
        
        fmt_size = struct.calcsize(STRUCT_PREFIX + fmt)
        data = self.readAll(fmt_size)
        
        return struct.unpack(STRUCT_PREFIX + fmt, data)
        
    def readVarLen (self, len_type) :
        """
            Return the data part of a <length><data> structure.
            len_type indicates what type length has (struct format code).
        """
        
        size, = self.readStruct(len_type)
        return self.readAll(size)
    
    def peek (self, len=None) :
        """
            Return a string representing what buf.read() would return
        """
        pos = self.buf.tell()
        data = self.read(len)
        self.buf.seek(pos)
        
        return data
    
    def mark (self) :
        """
            Set a mark that can be later rolled back to with .reset()
        """
        
        self.__position = self.buf.tell()
        
    def unmark (self) :
        """
            Remove the mark without affecting the current position
        """
        
        self.__position = None
    
    def reset (self) :
        """
            Rolls the buffer back to the position set earlier with mark()
        """
        
        if self.__position is not None :
            self.buf.seek(self.__position)
            self.__position = None
        else :
            raise Exception("Must mark() before calling reset()")
            
    def rewind (self) :
        """
            Seek back to the start of this buffer
        """
        self.buf.seek(0)
        
    def tail (self) :
        """
            Seek to the end of this buffer
        """
        self.buf.seek(0, 2)
        
    def chop (self) :
        """
            Snap the buffer in half at the current position and retain the remaining portion.
        """
        if self.__position is not None and self.__position < self.buf.tell() :
            raise Exception("chopping buffer would cause mark()'d position to be lost")
        
        buf = self.buf
        self.buf = StringIO()
        self.buf.write(buf.read())
        self.buf.seek(0)
        
        if self.__position :
            self.__position -= buf.tell()
    
    def tell (self) :
        """
            Return the current offset into the buffer
        """
        
        return self.buf.tell()
            
    def processWith (self, func) :
        """
            Call the given function with this buffer as an argument until it
                a) raises a NotEnoughDataError, whereupon the buffer is rolled
                   back to where it was before calling the function
                b) raises a StopIteration, whereupon we leave the buffer where
                   it was and return
                c) returns something (i.e. ret is not None), whereupon we
                   return that (and leave the current buffer position intact).
        """
        ret = None
        
        try :
            
            while ret is None :
                self.mark()  # mark the position of the packet we are processing
                ret = func(self)
                
        except NotEnoughDataError, e :
            self.reset() # reset position back to the start of the packet
            return e
            
        except StopIteration, e:
            self.unmark()
            return e # processed ok, but we don't want to process any further packets
        
        except :
            self.unmark()
            raise
        
        else :
            self.unmark()
            return ret
    
    def write (self, bytes) :
        """
            Write the given bytes to the current position in the buffer,
            overwriting any previous data, or making the buffer larger
        """
        
        return self.buf.write(bytes)
        
    def writeStruct (self, fmt, *args) :
        """
            Pack the given arguments with the given struct format, and write it
            to the buffer.
        """
        self.write(struct.pack(STRUCT_PREFIX + fmt, *args))
        
    def writeVarLen (self, data, len_type) :
        """
            Write a <length><data> field into the buffer. Len_type is the
            struct format code for the length field.
        """
        self.writeStruct(len_type, len(data))
        self.write(data)
        
    def extendFromStream (self, stream) :
        """
            I will copy the data from the given stream into the end of this
            buffer, preserving the current position and markers.
        """
        pos = self.buf.tell()
        
        self.buf.seek(0, 2)
        
        self.buf.write(stream.read())
        
        self.buf.seek(pos)
        
    def getvalue (self) :
        """
            Returns the value of the buffer, i.e. a string with the contents of
            the buffer from position zero to the end.
        """
        return self.buf.getvalue()
        
    def __nonzero__ (self) :
        return len(self.peek()) > 0 or ((self.wf and bool(self.wf)) or False)
