"""
    Python server component for TTD Patch multiplayer
"""

from twisted.internet import protocol, reactor

from cStringIO import StringIO
import struct
from datetime import datetime

CLIENT_MAGIC_STRING = 'TTDPATCH'
SERVER_MAGIC_STRING = 'TTDPATCHSERVER'
SERVER_VERSION = 1
SERVER_PORT = 5483

HANDSHAKE_TIMEOUT = 60
TICK_INTERVAL = 1 # 27.0/1000.0
RAND_CHECK_INTERVAL = 100   # send a 0x31 every x ticks

# dict of code -> (name, state-tuple, [(name, fmt)])
TYPES = {
    0x01: ('action_data', 'valid', [('data', '~B')]),
    0x02: ('action_flush', 'valid', []),
    
    0x30: ('heartbeat', None, []),
    0x31: ('heartbeat_with_rand', None, []),
    
    0x40: ('rand_value', 'valid', [('value', 'I')]),
    
    0x44: ('sync_get', None, []),
    0x45: ('sync_data', 'recv_sync', [('data', '~I')]),
    0x46: ('sync_heartbeat', None, []),
    
    0x80: ('server_quit', 'valid', [('password', '16s')]),
    0x81: ('kick_slot', 'valid', [('password', '16s')]),
    
    0xF1: ('slot_info', None, [('data', '~I')]),
    0xF2: ('set_slot', 'wait_client_slot', [('slot', 'B'), ('password', '16s')]),
    0xF3: ('slot_ok', None, []),
    0xF4: ('slot_err', None, []),
    0xF5: ('newgrf_info', None, []),
}

# dict of name -> (code, [(name, fmt)])
_type_names = dict([(name, (code, data_fmt)) for (code, (name, states, data_fmt)) in TYPES.iteritems()])

def hex (bytes) :
    return ' '.join(['%#04x' % ord(b) for b in bytes])
    
def log (msg) :
    n = datetime.now()
    print "%s.%03.0d %s" % (n.strftime('%H:%M:%S'), n.microsecond/1000, msg)

class NotEnoughDataError (Exception) : 
    pass

class Buffer (object) :
    # for mark/reset
    __position = None
    
    # the buffer
    buf = None
    
    def __init__ (self, str) :
        self.buf = StringIO(str)
    
    def read (self, size=None) :
        if size :
            return self.buf.read(size)
        else :
            return self.buf.read()
    
    def readAll (self, size) :
        """
            Returns either size bytes of data, or raises NotEnoughDataError
        """
        
        data = self.buf.read(size)
        
        if len(data) < size :
            raise NotEnoughDataError()
        else :
            return data
        
    def readStruct (self, fmt) :
        """
            Uses readAll to read struct data, and then unpacks it
        """
        
        fmt_size = struct.calcsize(fmt)
        data = self.readAll(fmt_size)
        
        return struct.unpack(fmt, data)
        
    def readVarLen (self, len_type) :
        """
            Return the data part of a <length><data> structure
            len_type indicates what type length has
        """
        
        size, = self.readStruct(len_type)
        return self.readAll(size)
    
    def peek (self, len=None) :
        pos = self.buf.tell()
        data = self.read(len)
        self.buf.seek(pos)
        
        return data
    
    def mark (self) :
        """
            Set a mark that can be later rolled back to with .reset()
        """
        
        self.__position = self.buf.tell()
    
    def reset (self) :
        """
            Rolls the buffer pack to the position set earlier with mark()
        """
        
        if self.__position is not None :
            self.buf.seek(self.__position)
            self.__position = None
        else :
            raise Exception("Must mark() before calling reset()")
            
    def processWith (self, func) :  
        try :
            while True :
                self.mark()  # mark the position of the packet we are processing
                func(self)
                
        except NotEnoughDataError :
            self.reset() # reset position back to the start of the packet

class ServerConnection (protocol.Protocol) :
    __state = 'init'
    
    # a string containing incomplete data from the previous recv
    recvbuffer = None
    
    # a delayed call used to timeout the handshake
    handshake_timeout = None
    
    # set to the connection that we are getting the sync data for
    sync_target = None
    
    # what player slot id we have
    player_slot = None
    
    # a list of action data that we collect in here until we get an action_flush
    action_buffer = None
    
    def __init__ (self) :
        self.recvbuffer = ''
        self.action_buffer = []
        
    def _set_state (self, state) :
        if state in ('init', 'wait_client_handshake', 'wait_client_slot', 'send_sync', 'valid', 'recv_sync') :
            self.__state = state
        else :
            raise Exception("Invalid state '%s'" % state)
    
    def _get_state (self) :
        return self.state
        
    # one of (init, wait_client_handshake, wait_client_slot, send_sync, valid, recv_sync)
    state = property(fget=_get_state, fset=_set_state)
    
    # connection state handling
    def connectionMade (self) :
        """
            State is now wait_client_handshake, start the timeout timer
        """
        self.state = 'wait_client_handshake'
        self.handshake_timeout = reactor.callLater(HANDSHAKE_TIMEOUT, self.err, "handshake timeout expired")
        self.log("connected")
    
    def connectionLost (self, reason) :
        """
            Recover:
                - if we have a player slot, clear it (currently no way to tell other players about that)
                - if we are syncing someone, try and get some other client to sync for them
        """
        
        self.log("lost connection")
        
        if self.player_slot :
            self.factory.delClient(self.player_slot)
            self.player_slot = None
        
        if self.sync_target :
            self.factory.syncDone() # maintain the correct ongoing sync count
            self.log("synch with %s was under way, attempting to relegate: %s" % (self.sync_target, self.factory.getSyncFor(self.sync_target) and 'OK' or 'bleh, failed'))
            self.sync_target = None
    
    # recv stuff
    def dataReceived (self, data) :
        """
            Buffer the data, if we are in the handshake stage we parse it directly, otherwise we call
            processPacket() until there's either no data or a packet fragment left
        """
        
        buf = Buffer(self.recvbuffer + data)
        
        # process packets until there are no more of them

        try :
            buf.processWith(self.processPacket)
        except Exception, e :
            self.err(e)
            raise
            
        # stuff remaining data back into recvbuf
        self.recvbuffer = buf.read()
        
    def processPacket (self, buf) :
        bytes = buf.peek()
        self.log("processing %d bytes: %s" % (len(bytes), hex(bytes)))
    
        # do we need to read the handshake?
        if self.state == 'wait_client_handshake' :
            magic_str, client_version = buf.readStruct('%dsI' % len(CLIENT_MAGIC_STRING))
            # stop the timeout
            self.handshake_timeout.cancel()
            
            if magic_str != CLIENT_MAGIC_STRING :
                raise Exception("wrong magic string received: %s" % magic_str)
            
            self.log("got handshake with version %s, sending slot_info" % client_version)
            
            # send our half of the handshake
            self.transport.write("%s%s" % (SERVER_MAGIC_STRING, struct.pack('IB', SERVER_VERSION, 0x00)))
            
            # send the slot info
            self.sendPacket('slot_info', self.getSlotInfo())
            self.state = 'wait_client_slot'
        else :    
            # read the frame/type
            frame, type = buf.readStruct('IB')
            
            # get the type info
            if type in TYPES :
                type_name, type_states, type_data_fmt = TYPES[type]
            else :
                raise Exception("unknown type %d" % type)
            
            # check the state
            if not type_states or self.state not in type_states :
                raise Exception("Can't send '%s' in state '%s'" % (type_name, self.state))
            
            # get the handler for it
            func = getattr(self, 'on_%s' % type_name, None)
            
            if not func :
                raise Exception("Type %s is not implemented" % type_name)
            
            # call the handler
            func(buf, frame)
    
    # the different packet types    
    def on_set_slot (self, buf, frame) :    
        slot, password = buf.readStruct('B16s')
        
        try :
            self.factory.setClient(slot, password, self)
        except Exception, e :
            self.sendPacket('slot_err')
        else :
            self.player_slot = slot
            self.sendPacket('slot_ok')
            self.doSync()
                    
    def on_sync_data (self, buf, frame) :
        data = buf.readVarLen('I')
        
        self.sync_target.gotSync(data)
        self.sync_target = None
        self.state = 'valid'
                
    def on_action_data (self, buf, frame) :
        data = buf.readVarLen('B')
        
        self.action_buffer.append(data)
                
    def on_action_flush (self, buf, frame) :     
        self.factory.addActions(self.action_buffer)
        self.action_buffer = []
                
    def on_rand_value (self, buf, frame) :       
        value, = buf.readStruct('I')
        
        self.factory.gotClientRand(self, frame, value)
    
    # send API
    def sendPacket (self, type_name, data='', frame=None) :
        if frame is None :
            frame = self.factory.frame
            
        type_code = _type_names[type_name][0]
        
        self.log("sending %s for frame %d with %d bytes: %s" % (type_name, frame, len(data), hex(data)))
        
        self.transport.write(struct.pack('IB%ds' % len(data), frame, type_code, data))
        
    def getSlotInfo (self) :
        p_mask = 0
        c_mask = 0
        p_strs = []
        
        for i, (p, c) in enumerate(self.factory.clients) :
            if p :
                p_mask |= 2**i
                
            if c :
                c_mask |= 2**1
            
            p_strs.append('player%d\0' % i)
        
        p_str = ''.join(p_strs)
        
        return struct.pack('IBB%ds' % len(p_str), (1 + 1 + len(p_str)), p_mask, c_mask, p_str)
    
    def doSync (self) :
        if self.factory.getSyncFor(self) :
            self.state = 'send_sync'
        else :
            # noone to sync with
            self.state = 'valid'
    
    def gotSync (self, data) :
        self.sendPacket('sync_data', struct.pack('I%ds' % len(data), len(data), data))
        self.state = 'valid'
        self.factory.syncDone()
    
    # API for Server
    def getSyncInfo (self, connection) :
        """
            Request sync data from this connection, and then give it to the given connection (gotSync())
        """
        
        if self.state != 'valid' :
            return False
        
        if self.sync_target :
            return False
        
        self.state = 'recv_sync'
        self.sync_target = connection
        self.sendPacket('sync_get')
        
        return True
    
    def pushAction (self, frame, action) :
        self.sendPacket('action_data', action, frame=frame)
    
    def doHeartbeat (self, frame) :
        if frame % RAND_CHECK_INTERVAL == 0 :
            type = 'heartbeat_with_rand'
        else :
            type = 'heartbeat'
            
        self.sendPacket(type, frame=frame)
    
    def onDesync (self) :
        """
            We sent an invalid random seed value
        """
        self.err("Wrong random seed value!")
    
    # logging
    def err (self, reason) :
        self.transport.loseConnection()
        log("%s errored out: %s" % (self, reason))
        
    def log (self, msg) :
        log("%s: %s" % (self, msg))
        
    def __str__ (self) :
        if self.player_slot :
            return "player %d" % self.player_slot
        else :
            addr = self.transport.getPeer()
            return "client %s:%d" % (addr.host, addr.port)
        
class Server (protocol.ServerFactory) :
    # the protocol that we use
    protocol = ServerConnection

    # list of (password, connection) tuples
    clients = None
    
    # our current frame number
    frame = None
    
    # actions to send for the next frame
    action_buffer = None
    
    # dict of frame -> list of (client, value) tuples
    rand_frames = None
    
    # do we have a sync ongoing?
    ongoing_sync_count = None
    
    # do we have any clients
    have_clients = None
    
    def __init__ (self) :
        self.clients = [(None, None) for x in xrange(8)]
        self.frame = 0
        self.action_buffer = []
        self.rand_frames = {}
        self.have_clients = False
        self.ongoing_sync_count = 0
        
        # first tick
        self.tick()
        
    def setClient (self, index, password, connection) :
        """
            Set the given connection as the given slot id with the given password.
            Raises an exception on errors
        """
        old_password, old_connection = self.clients[index]
        
        if old_connection :
            raise Exception("Slot already occupied")
        
        if not old_password or password == old_password :
            self.clients[index] = password, connection
        else :
            raise Exception("Wrong password for slot")
        
        self._updateHeartbeat()
    
    def delClient (self, index, remove_password=True) :
        """
            Clear out the given slot from the list of clients. 
            remove_password causes the password to be nulled
        """
        old_password, old_connection = self.clients[index]
        
        if not old_connection :
            raise Exception("Slot wasn't occupied")
        
        if remove_password :
            old_password = None
        
        self.clients[index] = old_password, None
        
        self._updateHeartbeat()
    
    def _updateHeartbeat (self) :
        """
            Figure out if we still/now have any clients
        """
        for pw, conn in self.clients :
            if conn :   # we do have at least one client, enable heartbeat if needed
                self.have_clients = True
                return
        
        self.have_clients = False
    
    def getSyncFor (self, conn) :
        """
            Ask some connected client to send the given client the sync data. 
            returns True if we found a client to do this, False if not (no other clients)
        """
        for pw, _conn in self.clients :
            if _conn and _conn.getSyncInfo(conn) :
                self.ongoing_sync_count += 1
                return True
                
        return False
    
    def syncDone (self) :
        """
            Signify that a sync has finished, heartbeats will start up again if this was the last one
        """
        self.ongoing_sync_count -= 1
    
    def addActions (self, actions) :
        """
            Add the given list of action data strings to the action buffer
        """
        self.action_buffer.extend(actions)
        
    def gotClientRand (self, conn, frame, value) :
        if frame not in self.rand_frames :
            self.rand_frames[frame] = []
            
        self.rand_frames[frame].append((conn, value))
        
        # once we receive rand values for a given frame from all clients, we compare them
        for frame, conns in self.rand_frames.items() :  # a copy, as we modify this while we iterate over it
            # dict of random seed value -> number of clients with this value
            values = {}
            
            if len(conns) >= len([p for p, c in self.clients if c]) :   # once we have values for all clients
                for conn, value in conns :
                    if conn.state != 'valid' :  # disregard clients that are now dead
                        conns.remove((conn, value))
                    else :
                        if value not in values :
                            values[value] = 1
                        else :
                            values[value] += 1
                
                if len(values.iterkeys()) > 1 :
                    # they disagree, figure out what the majority is
                    majority_value = None
                    majority_value_count = 0
                    
                    for value, count in values.iteritems() :
                        if count > majority_value_count :
                            majority_value_count = count
                            majority_value = value
                    
                    # kill all that disagree
                    for conn, value in conns :
                        if value != majority_value :
                            conn.onDesync()
                else :
                    # frame ok
                    del self.rand_frames[frame]
        
    def tick (self) :
        # schedule next tick
        reactor.callLater(TICK_INTERVAL, self.tick)
        
        # only do something if we have clients or no ongoing syncs
        if not self.have_clients or self.ongoing_sync_count > 0 :
            self.log("skipping tick as have_clients=%s, ongoing_sync_count=%s" % (self.have_clients, self.ongoing_sync_count))
            return
        else :
            self.log("tick: frame=%d, ongoing_sync_count=%d" % (self.frame, self.ongoing_sync_count))
        
        self.frame += 1
        
        actions = self.action_buffer
        self.action_buffer = []
        
        for pw, conn in self.clients :
            if conn :
                for action in actions : # send all actions to this client
                    conn.pushAction(self.rame, action)
                
                # then send the heartbeat
                conn.doHeartbeat(self.frame)
    
    def log (self, msg) :
        log("server: %s" % msg)
        
if __name__ == '__main__' :
    reactor.listenTCP(5483, Server())
    reactor.run()
    