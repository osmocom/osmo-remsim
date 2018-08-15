osmo-remsim - Osmocom remote SIM software suite
===============================================

This software suite is a work in progress.


remsim-client
-------------

The client interfaces with GSM phones / modems via dedicated "Card
Emulation" devices such as the Osmocom SIMtrace2 or sysmocom sysmoQMOD
board + firmware.  This hardware implements the ISO7816-3 electrical
interface and protocol handling and  passes any TPDU headers received
from the phone/modem to remsim-client for further processing of the
TPDUs associated to the given APDU transfer.

remsim-client connects via a RSPRO control connection to remsim-server
at startup and registers itself.  It will receive configuration data
such as the remsim-bankd IP+Port and the ClientId from remsim-server.

After receiving the configuration, remsim-client will establish a RSPRO
data connection to the remsim-bankd IP:Port.

As the USB interface for remote SIM in simtrace2.git uses one interface
per slot, we can implement the client in blocking mode, i.e. use
blocking I/O on the TCP/RSPRO side.  This simplifies the code compared
to a more complex async implementation.


remsim-bankd
------------

The remsim-bankd (SIM Bank Daemon) manages one given SIM bank.  The
initial implementation supports a PC/SC driver to expose any PC/SC
compatible card readers as SIM bank.

remsim-bankd initially connects via a RSPRO control connection to
remsim-server at startup, and will in turn receive a set of initial
[client,slot]:[bankd,slot] mappings.  These mappings determine which
slot on the client (corresponding to a modem) is mapped to which slot on
the SIM bank.  Mappings can be updated by remsim-server at any given
point in time.

remsim-bankd implements a RSPRO server, where it listens to connections
from remsim-clients.

As PC/SC only offers a blocking API, there is one thread per PC/SC slot.
This thread will perform blocking I/O on the socket towards the client,
and blocking API calls on PC/SC.

In terms of thread handling, we do:

* accept() handling in [spare] worker threads
** this means blocking I/O can be used, as each worker thread only has
   one TCP connection
** client identifies itself with client:slot
** lookup mapping based on client:slot (using mutex for protection)
** open the reader based on the lookup result

The worker threads initially don't have any mapping to a specific
reader, and that mapping is only established at a later point after the
client has identified itself.  The advantage is that the entire bankd
can live without any non-blocking I/O.

The main thread handles the connection to remsim-server, where it can
also use non-blocking I/O.  However, re-connection would be required, to
avoid stalling all banks/cards in the event of a connection loss to the
server.

worker threads have the following states:
* INIT (just started)
* ACCEPTING (they're blocking in the accept() call on the server socket fd)
* CONNECTED_WAIT_ID (TCP established, but peer not yet identified itself)
* CONNECTED_CLIENT (TCP established, client has identified itself, no mapping)
* CONNECTED_CLIENT_MAPPED (TCP established, client has identified itself, mapping exists)
* CONNECTED_CLIENT_MAPPED_CARD (TCP established, client identified, mapping exists, card opened)
* CONNECTED_SERVER (TCP established, server has identified itself)

Once the client disconnects, or any other error occurs (such as card I/O
errors), the worker thread either returns to INIT state (closing client
socket and reader), or it terminates.  Termination would mean that the
main thread would have to do non-blocking join to detect client
termination and then re-spawn clients, so the "return to INIT state"
approach seems to make more sense.

Open topics:
* detecting multiple connections from a server, logging this or even
  avoiding that situation
