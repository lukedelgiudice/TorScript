#!/usr/bin/env python3

############
# CS4501, Fall'24, HW1
# Your name: Luke Del Giudice
# Your computing ID: wcc5ub
############
# See Canvas for instructions

from stem.control import Controller
import stem.descriptor.remote
from stem import CircStatus
from stem import CircPurpose
import pycurl
import io
import json


def get_exit_policy(exit_fingerprint):
    try:
        # Fetch the server descriptor for the given fingerprint directly
        desc_iter = stem.descriptor.remote.get_server_descriptors(fingerprints=[exit_fingerprint])
        desc = next(desc_iter, None)  # Get the first descriptor from the iterator
       
        if desc:
            return desc.exit_policy.summary()  # Return the summarized exit policy
    except Exception as e:
        print(f"Error retrieving exit policy for {exit_fingerprint}: {e}")
   
    return []  # Return an empty list if no descriptor or error


with Controller.from_port(port = 9051) as controller:
    controller.authenticate("")
   
    ######################################
    # Part 1: retrieve the current circuits
    ######################################

    # SOURCES:
    # List Circuits
   
    built_general_circuits = [circ for circ in controller.get_circuits() if circ.status == CircStatus.BUILT and circ.purpose == CircPurpose.GENERAL]

    print("Circuits: [%s]" % len(built_general_circuits))

    for circ in built_general_circuits:

        print(f"\nCircuit ID: {circ.id}")

        guard = ("unknown", "unknown")
        middle = ("unknown", "unknown")
        exit = ("unknown", "unknown")
        exit_policy = []

        for i, entry in enumerate(circ.path):
          fingerprint, nickname = entry
          desc = controller.get_network_status(fingerprint, None)
          address = desc.address if desc else 'unknown'

          if i == 0:
                guard = (nickname, address)
          elif i == 1:
                middle = (nickname, address)
          elif i == 2:
                exit = (nickname, address)
                exit_policy = get_exit_policy(fingerprint)

        print(f"Guard: [{guard[0]}], [{guard[1]}]")
        print(f"Middle: [{middle[0]}], [{middle[1]}]")
        print(f"Exit: [{exit[0]}], [{exit[1]}]")

        print(f"Exit Policy: {exit_policy}")

        continue
       

    ######################################
    # Part 2: analyze all relays
    ######################################

    # SOURCES:
    # Bandwidth Heuristics (https://stem.torproject.org/tutorials/examples/bandwidth_stats.html)

    relay_bandwidth = 0
    guard_bandwidth = 0
    exit_bandwidth = 0

    relay_count = 0
    guard_count = 0
    exit_count = 0

    for desc in controller.get_network_statuses():
        relay_bandwidth += desc.bandwidth
        relay_count += 1

        if 'Guard' in desc.flags:
            guard_bandwidth += desc.bandwidth
            guard_count += 1

        if 'Exit' in desc.flags:
            exit_bandwidth += desc.bandwidth
            exit_count += 1


    print(f"Relays: [{relay_count}]")
    print(f"Guards: [{guard_count}]")

    if relay_bandwidth > 0:  # Division by zero
        guard_bandwidth_fraction = guard_bandwidth / relay_bandwidth
        exit_bandwidth_fraction = exit_bandwidth / relay_bandwidth
    else:
        guard_bandwidth_fraction = exit_bandwidth_fraction = 0

    print(f"Guard Bandwidth fraction: [{guard_bandwidth_fraction:.2f}]")
    print(f"Exits: [{exit_count}]")
    print(f"Exit Bandwidth fraction: [{exit_bandwidth_fraction:.2f}]")

        #continue

    ######################################
    # Part 3: use tor to access a website
    ######################################
   
    # SOURCES:
    # To Russia With Love (https://stem.torproject.org/tutorials/to_russia_with_love.html)

    SOCKS_PORT = 9050

    def query(url):
      output = io.BytesIO()

      query = pycurl.Curl()
      query.setopt(pycurl.URL, url)
      query.setopt(pycurl.PROXY, 'localhost')
      query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
      query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
      query.setopt(pycurl.WRITEFUNCTION, output.write)

      try:
        query.perform()
        return output.getvalue() #.decode('utf-8')
      except pycurl.error as exc:
        return "Unable to reach %s (%s)" % (url, exc)
       

    # Check my IP
    myip = json.loads(query("https://api.ipify.org?format=json"))
    print(myip['ip'])

   
    def scan(controller, path):
      circuit_id = controller.new_circuit(path, await_build = True)

      def attach_stream(stream):
        if stream.status == 'NEW':
          controller.attach_stream(stream.id, circuit_id)

      controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)

      try:
        controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us
       
        # make sure traffic is being routed through Tor
        check_page = query('https://check.torproject.org/')
        if 'Congratulations. This browser is configured to use Tor.' not in check_page:
          raise ValueError("Request didn't have the right content")

      finally:
        controller.remove_event_listener(attach_stream)
        controller.reset_conf('__LeaveStreamsUnattached')

    relay_fingerprints = [desc.fingerprint for desc in controller.get_network_statuses()]

    for fingerprint in relay_fingerprints:
        try:
            scan(controller, [fingerprint])
        except Exception as exc:
            print(f'Failed with relay {fingerprint}: {exc}')

    # Check my (new) IP. It should be different from the last one.
    myip = json.loads(query("https://api.ipify.org?format=json"))
    print(myip['ip'])
    
    