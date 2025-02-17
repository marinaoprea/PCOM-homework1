<h3>Overview</h3>
    <p>Current solution proposes an implementation of the dataplane algorithm
for a router.</p>
    <p>It implements best route searching using a static routing table that is then
managed in form of a binary trie in order to optimize multiple searches; on
network level, we construct dinamically a MAC table using the ARP protocol. </p>
<p>Additionally, ICMP control protocol is used in order to warn in case of target
being unreachable, either because of lack of route towards it or because of no
more time to live for the packet. </p>

<h3>Program flow</h3>
    <p>Firstly, we receive packets on any of the interfaces. For an IPv4 packet, we
recalculate the checksum in order to assure data was not harmed. If it was,
the packet is dropped.</p>
    <p>Then we decrease TTL and recalculate the checksum; if there is no more TTL,
we construct an ICMP packet to announce the sender of the original packet.</p>
    <p>Otherwise we search the best route towards the target IP. If target is
unreachable, we construct an ICMP packet to announce the sender of the original
packet.</p>
    <p>Otherwise, we have a next hop and try to route our packet through Ethernet. 
We search in our MAC table for the MAC address of the next hop. If we do not
have it, we send an ARP broadcast request, targeting the ip address of the next
hop. We enque the packet in a local queue until the reply arrives in order to
route other packets meanwhile.</p>
<p>
    If we receive an ARP request for the router itself, we complete the reply
and send it towards the original sender.</p>
<p>
    If we receive an ARP reply, we register it in our local MAC table and then
check if any packets from the queue are now ready to be sent. We do not check if
the packets requested the newly arrived MAC, we parse the queue as long as any
of the packets are ready to be sent. We do not worry about the order of the
responses because as long as the queue is not empty, it means a request was sent
and a reply is still waited for and as we memorize all given replies, all 
packets are to be taken care of at some point, regardless of the order of the
arrivals.</p>

<p>
    If we receive an ICMP Echo request, we response with an Echo reply.</p>


<h3>Technical details</h3>
    <p>Enqued packets are allocated on heap beacuse we shall need the information 
later after local buffer on stack shall be overwritten.</p>


<h3>Trie implementation</h3>
    <p>We enroll given prefixes in the routing table in a binary trie. We mark the
last node as containing a response. The information contained is the index in
the routing table in order to optimize memory, as the routing table was already
allocated. If there are more than one prefixes equal, we shall memorize all of 
them. We have no criteria to differentiate in this case, so we always return the
first option.</p>
<p>
    On search, we match the given ip with the prefixes as much as possible, 
going as deeply as possible in the trie.</p>
    <b>Time complexity</b>: <ul> <li>O(32 * n) -> O(n) for construction</li>
                     <li>O(32) -> O(1) for search</li></ul>
    <b>Space complexity</b>: <ul> <li>O(n) (one final node for each prefix, constant number of
                          internal nodes for each prefix) </li></ul></p>
