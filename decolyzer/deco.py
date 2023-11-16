import logging
import paramiko
import pyshark
import time
from scp import SCPClient
logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

class Ssh(object):
    """Class to create/terminate connection to linux/unix OS on a given port"""

    def __init__(self, ip, username='root', password='password', port=22, timeout=120):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = int(port)
        self.timeout = int(timeout)
        self.session = paramiko.SSHClient()
        self.session.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        self.session.connect(self.ip, port=self.port, timeout=self.timeout,
                             username=self.username, password=self.password,
                             look_for_keys=False, allow_agent=False)

    def disconnect(self):
        self.session.close()

    def execute(self, command):
        stdin, stdout, stderr = self.session.exec_command(command.strip())
        return stdout.read().decode('utf-8')

    @property
    def connected(self):
        return self.session._transport is not None and \
               self.session._transport.active


def decogoat(hostip, port=29999, username='root',
             password='password', command='tcpdump -i eth1 -w /tmp/capt.pcap',
             processname='tcpdump', change_file_permission=False,
             chmod_cmd='chmod 777 /tmp/capt.pcap', channel_creation_sleep=0,
             delete_file=False, delete_cmd='rm -rf /tmp/capt.pcap',
             terminate_process=True, terminate_cmd='killall -e tcpdump'):
    """
    Function to start a process/script (e.g. tcpdump, top), run your function, end a process/script
    Make sure to manually connect to the targeted host with the intended username/password and execute
        a command to make sure that it does work and will not impact automation.
    :param hostip: ip address of a host machine
    :param port: default port is 29999 
        (connection to linux/unix OS to execute commands or processes e.g. top/tcpdump/ls/cat)
    :param username: username to connect with
    :param password: password fo the username
    :param command: comamnd to be executed before running your own function code, (e.g. tcpdump command)
    :param processname: name of the process to be invoked and if required to be terminated
    :param change_file_permission: (default: False)
        if file gets created and requires a permission change for remote copy
    :param chmod_cmd: command to change the permission on the file for remote copy
    :param channel_creation_sleep: (default: 0) sleep time pre/post channel creation and command execution
    :param delete_file: (default: False) if file is present, if required, delete it first
    :param delete_cmd: process/file deletion command
    :param terminate_process: (default: True) if true, process will be terminated
    :param terminate_cmd: command to terminate the targeted process
    :return: True if all steps passes Or False if failure is encountered
    :usage:
     @decogoat('10.10.10.2', port=29999, username='root',
                    password='PassWord',
                    command='tcpdump -i eth0 -w /tmp/capt.pcap',
                    change_file_permission=True, chmod_cmd='chmod 777 /tmp/capt.pcap',
                    channel_creation_sleep=0, delete_file=True,
                    delete_cmd='rm -rf /tmp/capt.pcap', terminate_cmd='killall -e tcpdump')
    def create_netconf_session(username, password, *args):
        connectobj = Sessioncreation('10.10.10.2', "CLI", username, password, "22")
        connectobj.connect()
    """
    def inner(funname):
        def wrapper(*args, **kwargs):
            log.info("\n\ndecogoat(START) - Connect to the port")
            try:
                linuxssh = Ssh(hostip, port=port, username=username, password=password)
                linuxssh.connect()
            except Exception as e:
                log.error("SSH connection failed!\n Exception:\n {}".format(str(e)))
                return False
            log.info("Port (SSH) to {} is connected!".format(hostip))

            try:
                if delete_file:
                    channel_created, channel_session = channel_creation(linuxssh, delete_cmd, channel_creation_sleep)
                    if channel_created:
                        log.info("File is deleted successfully")
                        channel_session.close()
                    else:
                        log.error("Fail: File deletion is failed!")
                        return False

                channel_created, channel_session = channel_creation(linuxssh, command, channel_creation_sleep)
                if channel_created:
                    log.info("Channel is created successfully")
                else:
                    log.error("Fail: Channel creation is failed")
                    return False

                out = channel_session.recv(-1)
                log.info("Command output:\n{}".format(out.decode()))
                channel_session.close()

                stdin, stdout, stderr = linuxssh.session.exec_command("pgrep {}".format(processname))
                log.info("Before -  process details: {}".format(stdout))
                process_ids_str = stdout.read().decode('utf-8')
                log.info("Before - process id(or ids) are:\n" + process_ids_str)

                if process_ids_str == '':
                    log.error("Fail: Process - {} - is NOT running!".format(processname))
                    return False
                else:
                    log.info("Pass: Process - {} - is running!".format(processname))

                funname(*args, **kwargs)
            except Exception as e:
                log.error("Error reported:\n {}".format(str(e)))
                return False

            if terminate_process:
                log.info("Terminate the process: {}".format(processname))
                try:
                    channel_created, channel_session = channel_creation(linuxssh, terminate_cmd, channel_creation_sleep)
                    if channel_created:
                        log.info("Channel to terminate the command is created successfully")
                    else:
                        log.error("Fail: Channel to terminate the command is failed")
                        return False
                    channel_session.close()
                except Exception as e:
                    log.error("After Error reported:\n {}".format(str(e)))
                    return False

                stdin, stdout, stderr = linuxssh.session.exec_command("pgrep {}".format(processname))
                log.info("After -  process details: {}".format(stdout))

                if stdout.read().decode() == '':
                    log.info("Pass: Process - {} - is terminated successfully!".format(processname))
                else:
                    log.error("After(Fail) -  process ids are:\n" + stdout.read().decode('utf-8'))
                    log.error("Fail: Process - {} - is not terminated!".format(processname))
                    return False

            if change_file_permission:
                channel_created, channel_session = channel_creation(linuxssh, chmod_cmd, channel_creation_sleep)
                if channel_created:
                    log.info("Channel to change permission on file is created successfully")
                    channel_session.close()
                else:
                    log.error("Fail: Channel creation to change permission on file is failed")
                    return False

            log.info("Terminate the SSH connection")
            linuxssh.disconnect()
            log.info("decogoat(END)")
            return True
        return wrapper
    return inner


def channel_creation(ssh_object, cmd, channel_creation_sleep=0):
    """
    function to create a channel and execut.e command on it
    :param paramiko_object: (ssh connection object) channel is created off of paramiko object
    :param cmd: command to be executed once channel is created
    :param channel_creation_sleep: sleep time post command execution before closing the channel
           For some linux commands, closing the channel right after command execution will fail the command execution.
    :return: [True, channel_session] or [False, channel_session]
    :usage
     channel_created, channel_session = channel_creation(linuxssh, chmod_cmd, channel_creation_sleep)
         if channel_created:
             log.info("Channel to change permission on file is created successfully")
             channel_session.close()  ##  Observe that the session is getting closed outside of this function
         else:
             log.info("Fail: Channel creation to change permission on file is failed")
             return False
    """
    log.info("\n\nchannel_creation(START) - Open paramiko transport and Create a Channel")
    transport = ssh_object.session.get_transport()
    channel_session = transport.open_session()
    channel_session.get_pty()
    channel_session.set_combine_stderr(True)
    channel_session.set_combine_stderr(True)

    log.info("Channel - command: {}".format(cmd))
    try:
        channel_session.exec_command(cmd)
    except Exception as e:
        log.error("Channel - Error reported:\n {}".format(str(e)))
        return [False, channel_session]

    time.sleep(channel_creation_sleep)

    out = channel_session.recv(-1)
    log.info("channel_creation(END) - Channel Command output:\n{}".format(out.decode()))

    return [True, channel_session]


def scp_operation(fromip, username='root', password='PassWord', port=29999,
                   from_path='/tmp/capt.pcap', destination_path='/tmp/',
                   change_file_permission=False, chmod_cmd='chmod 777 /tmp/capt.pcap',
                   channel_creation_sleep=0, get_present=1, put_present=0):
    """
    Function to copy a file from remote shelf to local system
    OR
    to copy a file from local shelf to remote system
    :param fromip: remote host ip to fetch the file from
    :param username: username to log into remote host
    :param password: password to log into remote host
    :param port: (default is: 29999) remote host port to connect to execute scp clis
    :param from_path: file to be copied from remote host
    :param destination_path: file to be copied to this path
    :param change_file_permission: if file requires a permission change to copy it to local machine
    :param chmod_cmd: command to change the permission on the file to allow the copy to local machine
    :param channel_creation_sleep: sleep time post (channel creation and command execution)
           without this sleep, closing the channel too quick will not execute the chmod command successfully
    :param get_present: to get operation to obtain file from remote server  to local machine
    :param put_present: to put operation to copy file from local machine to remote server
    :return: True if copy operation is pass, Fail otherwise
    :usage
    scp_operation('10.10.10.2', username='root', password='PassWd', port=29999,
                             from_path='/tmp/capt.pcap', destination_path='/tmp/capt.pcap',
                             change_file_permission=True, chmod_cmd='chmod 777 /tmp/capt.pcap',
                             channel_creation_sleep=0)
    """
    log.info("\n\nscp_operation(START) - Create SSH session to host ip:{0} and Port:{1}".format(fromip, port))
    try:
        sshobj = Ssh(fromip, username=username, password=password, port=port)
        sshobj.connect()
    except Exception as e:
        log.error("SSH connection failed!\n Exception:\n {}".format(str(e)))
        return False
    log.info("SSH session is created!")

    if change_file_permission:
        channel_created, channel_session = channel_creation(sshobj, chmod_cmd, channel_creation_sleep)
        if channel_created:
            log.info("copy_operation: Channel to change permission on file is created successfully")
            channel_session.close()
        else:
            log.error("copy_operation: Fail: Channel creation to change permission on file is failed")
            return False

    try:
        scp = SCPClient(sshobj.session.get_transport())
        if get_present:
            scp.get(from_path, destination_path)
        if put_present:
            scp.put(from_path, destination_path)
    except Exception as e:
        log.error("SCP operation is failed!\n Exception:\n {}".format(str(e)))
        return False

    if get_present:
        log.info("SCP from remote to local host - from:{} to:{} is completed".format(from_path, destination_path))
        log.info("GET operation is completed.".format(destination_path))
    if put_present:
        log.info("SCP from local to remote host - from:{} to:{} is completed".format(from_path, destination_path))
        log.info("PUT operation is completed.")
    log.info("scp_operation:(END)")

    return True


def analyze_capture(cap_path, display_filter='', keep_packets=True, only_summaries=False,
                    disable_protocol='', decryption_key='', encryption_type='WPA-PWK', tshark_path=''):
    """
    Function to analyze the capture and return a dictionary
    :param cap_path: path to the capture file
    :param display_filter: apply filter to narrow down the protocol specific traffic i.e. ssh/dns/radius
    :param keep_packets: Whether to keep packets after reading them via next().
           Used to conserve memory when reading large caps.
    :param only_summaries: Only produce packet summaries, much faster but includes very little information
    :param disable_protocol: Disable detection of a protocol (tshark > version 2)
    :param decryption_key: Key used to encrypt and decrypt captured traffic.
    :param encryption_type: Standard of encryption used in captured traffic
           (must be either 'WEP', 'WPA-PWD', or 'WPA-PWK'. Defaults to WPA-PWK.
    :param tshark_path: Path of the tshark binary
    :return: False if failure is encountered. if success, returned e.g. [True, cap_obj, {"total_pkts:114}]
    :usage
    # To see packets only with SSH protocol layer in it
    cpt_ret = analyze_capture("/tmp/capt.pcap", display_filter="ssh")
    cpt_ret = analyze_capture("/tmp/capt.pcap", display_filter="radius") # This will show access-request/accept only
    cpt_ret = analyze_capture("/tmp/capt.pcap")
    if cpt_ret[0]:
        log.info("total packets returned:{}".format(cpt_ret[2]['total_pkts']))
        #cpt_ret[0] is True
        #cpt_ret[1] is to level capture object
        #  cat_ret[1][0] first packet obj
        #  cat_ret[1][1] second packet obj
        #  cat_ret[1][total_packets-1] last packet obj
        #cpt_ret[2] is total packets captured
        capobj_first_pkt = cpt_ret[1][0]
    (Pdb) dir(capobj_first_pkt)
    ['DATA', '__bool__', '__class__', '__contains__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__',
    '__format__', '__ge__', '__getattr__', '__getattribute__', '__getitem__', '__getstate__', '__gt__', '__hash__',
    '__init__', '__init_subclass__', '__le__', '__len__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__',
    '__reduce_ex__', '__repr__', '__setattr__', '__setstate__', '__sizeof__', '__str__', '__subclasshook__',
    '__weakref__', '_packet_string', 'captured_length', 'eth', 'frame_info', 'get_multiple_layers', 'get_raw_packet',
    'highest_layer', 'interface_captured', 'ip', 'layers', 'length', 'number', 'pretty_print', 'show', 'sniff_time',
    'sniff_timestamp', 'tcp', 'transport_layer']
    (Pdb) dir(capobj_first_pkt.ip)
    ['__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__',
    '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__',
    '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__',
    '__sizeof__', '__slots__', '__str__', '__subclasshook__', '_all_fields', '_field_prefix', '_get_all_field_lines',
    '_get_all_fields_with_alternates', '_get_field_or_layer_repr', '_get_field_repr', '_layer_name',
    '_pretty_print_layer_fields', '_sanitize_field_name', 'addr', 'checksum', 'checksum_bad', 'checksum_good',
    'dsfield', 'dsfield_dscp', 'dsfield_ecn', 'dst', 'dst_host', 'field_names', 'flags', 'flags_df', 'flags_mf',
    'flags_rb', 'frag_offset', 'get', 'get_field', 'get_field_by_showname', 'get_field_value', 'has_field', 'hdr_len',
    'host', 'id', 'layer_name', 'len', 'pretty_print', 'proto', 'raw_mode', 'src', 'src_host', 'ttl', 'version']
    (Pdb) print(capobj_first_pkt.ip.src_host)
    10.10.10.2
    (Pdb) print(capobj_first_pkt.ip.dst_host)
    10.179.192.241
    (Pdb) dir(capobj_first_pkt.eth)
    ['__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__',
    '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__',
    '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__',
    '__setstate__', '__sizeof__', '__slots__', '__str__', '__subclasshook__', '_all_fields', '_field_prefix',
    '_get_all_field_lines', '_get_all_fields_with_alternates', '_get_field_or_layer_repr', '_get_field_repr',
    '_layer_name', '_pretty_print_layer_fields', '_sanitize_field_name', 'addr', 'dst', 'field_names',
    'get', 'get_field', 'get_field_by_showname', 'get_field_value', 'has_field', 'ig', 'layer_name', 'lg',
    'pretty_print', 'raw_mode', 'src', 'type']
    (Pdb) print(capobj_first_pkt.eth.src)
    74:87:bb:c9:3f:e4
    (Pdb) print(capobj_first_pkt.eth.dst)
    40:f0:78:c1:d9:f7
    (Pdb) dir(capobj_first_pkt.tcp)
    ['', '__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__',
    '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__',
    '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__',
    '__sizeof__', '__slots__', '__str__', '__subclasshook__', '_all_fields', '_field_prefix', '_get_all_field_lines',
    '_get_all_fields_with_alternates', '_get_field_or_layer_repr', '_get_field_repr', '_layer_name',
    '_pretty_print_layer_fields', '_sanitize_field_name', 'ack', 'analysis', 'analysis_bytes_in_flight',
    'checksum', 'checksum_bad', 'checksum_good', 'dstport', 'field_names', 'flags', 'flags_ack', 'flags_cwr',
    'flags_ecn', 'flags_fin', 'flags_ns', 'flags_push', 'flags_res', 'flags_reset', 'flags_syn', 'flags_urg',
    'get', 'get_field', 'get_field_by_showname', 'get_field_value', 'has_field', 'hdr_len', 'layer_name', 'len',
    'nxtseq', 'option_kind', 'option_len', 'options', 'options_timestamp_tsecr', 'options_timestamp_tsval',
    'options_type', 'options_type_class', 'options_type_copy', 'options_type_number', 'port', 'pretty_print',
    'raw_mode', 'seq', 'srcport', 'stream', 'window_size', 'window_size_scalefactor', 'window_size_value']
    (Pdb) print(capobj_first_pkt.tcp.srcport)
    29999
    (Pdb) print(capobj_first_pkt.tcp.dstport)
    32772
    (Pdb)

    Radius protocols:
    cpt_ret = analyze_capture("/tmp/capt.pcap", display_filter="radius")
    (Pdb) capobj_first_pkt = cpt_ret[1][0]
    (Pdb) dir(capobj_first_pkt.radius)
    ['', '__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__', '__sizeof__', '__slots__', '__str__', '__subclasshook__', '_all_fields', '_field_prefix', '_get_all_field_lines', '_get_all_fields_with_alternates', '_get_field_or_layer_repr', '_get_field_repr', '_layer_name', '_pretty_print_layer_fields', '_sanitize_field_name', 'authenticator', 'calling_station_id', 'code', 'field_names', 'get', 'get_field', 'get_field_by_showname', 'get_field_value', 'has_field', 'id', 'layer_name', 'length', 'nas_identifier', 'nas_ip_address', 'nas_port', 'nas_port_type', 'pretty_print', 'raw_mode', 'req', 'service_type', 'user_name', 'user_password_encrypted']
    (Pdb) capobj_first_pkt.radius.nas_ip_address
    '10.10.10.2'
    (Pdb) capobj_first_pkt.radius.nas_identifier
    '6000-ABC-Switch'
    (Pdb) capobj_first_pkt.radius.nas_port
    '1415531'
    (Pdb) capobj_first_pkt.radius.pretty_print
    <bound method BaseLayer.pretty_print of <RADIUS Layer>>
    (Pdb) capobj_first_pkt.radius.pretty_print()
    Layer RADIUS
    :       Code: Access-Request (1)
            Packet identifier: 0x7c (124)
            Length: 122
            Authenticator: 3b1cab8e9f7b2688852204ebfe749aeb
            Attribute Value Pairs
            User-Name: su
            User-Password (encrypted): f106af72e91ad3c4ea17b864a1aceb1f
            NAS-Identifier: 6000-ABC-Switch
            NAS-Port: 1415531
            NAS-Port-Type: Virtual (5)
            Service-Type: Authenticate-Only (8)
            Calling-Station-Id: /ssh_shell_10.179.192.241:60826
            NAS-IP-Address: 10.10.10.2 (10.10.10.2)
            AVP: l=4  t=User-Name(1): su
            AVP: l=18  t=User-Password(2): Encrypted
            AVP: l=23  t=NAS-Identifier(32): 6000-ABC-Switch
            AVP: l=6  t=NAS-Port(5): 1415531
            AVP: l=6  t=NAS-Port-Type(61): Virtual(5)
            AVP: l=6  t=Service-Type(6): Authenticate-Only(8)
            AVP: l=33  t=Calling-Station-Id(31): /ssh_shell_10.179.192.241:60826
            AVP: l=6  t=NAS-IP-Address(4): 10.10.10.2
    (Pdb)
    """
    log.info("\n\nanalyze_capture(START) - Start the capture analysis")
    try:
        cap = pyshark.FileCapture(input_file=cap_path, display_filter=display_filter,
                                  keep_packets=keep_packets, only_summaries=only_summaries,
                                  disable_protocol=disable_protocol, decryption_key=decryption_key,
                                  encryption_type=encryption_type, tshark_path=tshark_path)
        cap.load_packets()
    except Exception as e:
        log.error("analyze_capture: Error reported:\n {}".format(str(e)))
        return [False]

    total_pkts = len(cap)
    if total_pkts:
        if display_filter:
            log.info("Total packets(filter:{}) captured: {}".format(display_filter, total_pkts))
        else:
            log.info("Total packets captured: {}".format(total_pkts))

    log.info("analyze_capture(END)")
    return [True, cap, {"total_pkts":total_pkts}]

