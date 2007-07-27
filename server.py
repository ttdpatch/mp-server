"""
    Python server component for TTD Patch multiplayer
"""

from twisted.internet import protocol, reactor

from cStringIO import StringIO
import struct
from datetime import datetime

SERVER_VERSION = 1
SERVER_PORT = 5483

HANDSHAKE_TIMEOUT = 60
TICK_INTERVAL = 1 # 27.0/1000.0
RAND_CHECK_INTERVAL = 100   # send a heartbeat_with_rand every x ticks

# dict of code -> (name, state-tuple, [(name, fmt)])
CLIENT_TYPES = {
    0x01: ('action', 'valid'),
    0x02: ('action_flush', 'valid'),
    
    0x40: ('rand_value', 'valid'),
    
    0x45: ('sync_data', 'recv_sync'),
    
    0x50: ('rename', 'valid'),
    0x54: ('chat', 'valid'),
    
    0x80: ('server_quit', 'valid'),
    0x81: ('player_kickban', 'valid'),
    0x82: ('player_kick', 'valid'),
    
    0xF0: ('hello', 'wait_hello'),
    0xF1: ('password', 'wait_password'),
    0xF3: ('set_slot', 'wait_slot'),
    0xF5: ('set_metainfo', 'wait_metainfo'),
}

SERVER_TYPES = {
    'action': 0x01,
    
    'heartbeat': 0x30,
    'heartbeat_with_rand': 0x31,
    
    'sync_get': 0x44,
    'sync_data': 0x45,
    
    'client_join': 0x51,
    'client_rename': 0x52,
    'client_quit': 0x53,
    'chat': 0x54,
    
    'hello': 0xF0,
    'slot_info': 0xF2,
    'initial_client': 0xF4,
    'wait_sync': 0xF6,
    
    'error': 0xFE,
    'abort': 0xFF,
}

class BaseClientError (Exception) :
    type = None
    code = None
    
    def __init__ (self, type=None) :
        self.type = type
    
    def errorCode (self) :
        return self.code | (self.type << 8)
    
class BaseClientAbort (Exception) :
    pass
    
class InvalidStateError (BaseClientAbort) :
    code = 0x01
    
class ZeroLengthError (BaseClientAbort) :
    code = 0x02

class InvalidFrameNumberError (BaseClientAbort) :
    code = 0x03
    
class InvalidRandomSeedError (BaseClientAbort) :
    code = 0x04
    
class WrongVersionError (BaseClientAbort) :
    code = 0x05
    
class ServerIsFullError (BaseClientAbort) :
    code = 0x06
    
class UnknownTypeError (BaseClientAbort) :
    code = 0x07
    
class WrongPasswordError (BaseClientError) :
    code = 0x10
    
class InvalidPlayerError (BaseClientError) :
    code = 0x11
    
class SlotInUseError (BaseClientError) :
    code = 0x12
    
class InvalidNameError (BaseClientError) :
    code = 0x13
    
class NameInUseError (BaseClientError) :
    code = 0x14

def log (msg) :
    n = datetime.now()
    print "%s.%03.0d %s" % (n.strftime('%H:%M:%S'), n.microsecond/1000, msg)

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
    
    # the player's name
    player_name = None
    
    def __init__ (self) :
        self.recvbuffer = ''
        self.action_buffer = []
        
    def _set_state (self, state) :
        if state in ('init', 'wait_hello', 'wait_password', 'wait_slot', 'wait_metainfo', 'send_sync', 'valid', 'recv_sync') :
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
        self.state = 'wait_hello'
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
        
        buf = buffer.Buffer(self.recvbuffer + data)
        
        # process packets until there are no more of them

        try :
            buf.processWith(self.processPacket)
        except BaseClientAbort, e :
            self.do_abort(e.errorCode())
            
            self.log("closing connection")
            self.transport.loseConnection()
            
        except BaseClientError, e :
            self.do_error(e.errorCode())
            
        except Exception, e :
            self.log("unknown exception %s: %s" % (type(e), e))
            
            self.log("closing connection")
            self.transport.loseConnection()
            
            raise
            
        # stuff remaining data back into recvbuf
        self.recvbuffer = buf.read()
        
    def processPacket (self, buf) :
        bytes = buf.peek()
        self.log("processing %d bytes: %s" % (len(bytes), hex(bytes)))
        
        type, = buf.readStruct('B')
        
        try :
            try :
                type_name, type_states = TYPES[type]
            except IndexError :
                self.log("unknown type %d" % type)
                raise UnknownTypeError()
            
            if self.state not in type_states :
                self.log("can't do %s in state %s" % (type_name, self.state))
                raise InvalidStateError()
                
            # get the handler for it
            func = getattr(self, 'on_%s' % type_name, None)
            
            if not func :
                self.log("type %d is not implemented" % (type_name, ))
                raise UnknownTypeError()
            
            # call the handler
            func(buf)
        except BaseClientError, e :
            e.type = type
            raise
        
    # sending replies
    def _startSend (self, type_name) :
        buf = buffer.Buffer()
        buf.writeStruct('B', SERVER_TYPES[type_name])
        
        return buf
        
    def _doSend (self, buf) :
        # write out the reply
        self.transport.write(buf.getvalue())        
    
    # in/out methods
    def do_abort (self, error_code) :
        o = self._startSend('abort')
        o.writeStruct('H', error_code)
        self._doSend(o)
    
    def do_error (self, error_code) :
        o = self._startSend('error')
        o.writeStruct('H', error_code)
        self._doSend(o)
        
    def on_hello (self, i, o) :
        client_version, = i.readStruct('I')
        
        # stop the timeout
        self.handshake_timeout.cancel()
        
        self.log("got handshake with version %s, sending slot_info" % client_version)
        
        # send our half of the handshake
        o.writeStruct('IB', SERVER_VERSION, 0x00)
        
        # send the slot info
        self.do_slot_info()
        self.state = 'wait_client_slot'
   
    def do_slot_info (self) :
        o = self._startSend('slot_info')
        
        pwd_mask = 0
        used_mask = 0
        name_strs = []
        
        for id, (pwd, client) in enumerate(self.factory.clients) :
            if pwd :
                pwd_mask |= 2**i
                
            if client :
                used_mask |= 2**1
            
            name_strs.append(client.player_name + '\x00')
        
        names_str = ''.join(name_strs)
        
        o.writeStruct('BB', pwd_mask, used_mask)
        o.writeVarLen(names_str, 'H')
        
        self._doSend(o)
        
    def on_set_slot (self, i) :    
        slot, password = i.readStruct('B16s')
        
        try :
            is_initial_client = self.factory.setClient(slot, password, self)
        except :
            raise
        else :
            self.player_slot = slot
            
            if is_initial_client :
                self.do_initial_client()
            else :
                self.do_wait_sync()
                self.doSync()
            
    def do_initial_client (self) :
        o = self._startSend('intial_client')
        
        self._doSend(o)
        
        self.state = 'wait_metainfo'
        
    def do_wait_sync (self) :
        o = self._startSend('wait_sync')
        
        self._doSend(o)
        
        self.state = 'send_sync'
                    
    def on_sync_data (self, i) :
        data = i.readVarLen('I')
        
        self.sync_target.gotSync(data)
        self.sync_target = None
        
        self.state = 'valid'
    
    def do_sync_data (self, data) :
        o = self._startSend('sync_data')
        
        o.writeVarLen(data, 'I')
        
        self._doSend(o)
                
    def on_action (self, i) :
        data = i.readVarLen('B')
        
        self.action_buffer.append(data)
                
    def on_action_flush (self, i) :     
        self.factory.addActions(self.action_buffer)
        self.action_buffer = []
        
    def do_action (self, frame, data) :
        o = self._startSend('action')
        
        o.writeStruct('I', frame)
        o.writeVarLen(data, 'B')
        
        self._doSend(o)
        
    def do_heartbeat (self, frame) :
        o = self._startSend('heartbeat')
        
        o.writeStruct('I', frame)
        
        self._doSend(o)
        
    def do_heartbeat_with_rand (self, frame) :
        o = self._startSend('heartbeat_with_rand')
        
        o.writeStruct('I', frame)
        
        self._doSend(o)
                
    def on_rand_value (self, i) :       
        frame, value = i.readStruct('II')
        
        self.factory.gotClientRand(self, frame, value)
        
    def do_sync_get (self) :
        o = self._startSend('sync_data')
        
        self._doSend(o)
    
    # state-handling methods
    def doSync (self) :
        """
            Ask the factory to get someone to sync us up
       """
       
        self.factory.getSyncFor(self)
    
    def gotSync (self, data) :
        """
            We have received the sync data from some other client
        """
        
        self.do_sync_data(data)
        
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
        self.do_sync_get()
        
        return True
    
    def pushAction (self, frame, action) :
        self.do_action(frame, data)
    
    def doHeartbeat (self, frame) :
        if frame % RAND_CHECK_INTERVAL == 0 :
            self.do_heartbeat_with_rand(frame)
        else :
            self.do_hearbeat(frame)
    
    def onDesync (self) :
        """
            We sent an invalid random seed value
        """
        
        self.abort(InvalidRandomSeedError(CLIENT_TYPES.index('rand_value')))
        
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
            raise SlotInUseError()
        
        if not old_password or password == old_password :
            self.clients[index] = password, connection
        else :
            raise WrongPasswordError()
        
        self._updateHeartbeat()
        
        # is this the only client?
        return len([0 for p, c in self.clients if c]) == 1
    
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
    reactor.listenTCP(SERVER_PORT, Server())
    reactor.run()
    