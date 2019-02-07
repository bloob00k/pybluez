from _bluetooth import *
import struct
import sys

HCI_CHANNEL_CONTROL = 3
BTPROTO_HCI =   1

MGMT_OP_START_DISCOVERY	= 0x0023
MGMT_OP_STOP_DISCOVERY  = 0x0024

MGMT_EV_CMD_COMPLETE =		0x0001
MGMT_EV_CMD_STATUS =		0x0002
MGMT_EV_CONTROLLER_ERROR =	0x0003
MGMT_EV_INDEX_ADDED =		0x0004
MGMT_EV_INDEX_REMOVED =		0x0005
MGMT_EV_NEW_SETTINGS =		0x0006
MGMT_EV_CLASS_OF_DEV_CHANGED =	0x0007
MGMT_EV_LOCAL_NAME_CHANGED =	0x0008
MGMT_EV_NEW_LINK_KEY =		0x0009
MGMT_EV_NEW_LONG_TERM_KEY =	0x000A
MGMT_EV_DEVICE_CONNECTED =	0x000B
MGMT_EV_DEVICE_DISCONNECTED =	0x000C
MGMT_EV_CONNECT_FAILED =	0x000D
MGMT_EV_PIN_CODE_REQUEST =	0x000E
MGMT_EV_USER_CONFIRM_REQUEST =	0x000F
MGMT_EV_USER_PASSKEY_REQUEST =	0x0010
MGMT_EV_AUTH_FAILED =		0x0011
MGMT_EV_DEVICE_FOUND =		0x0012
MGMT_EV_DISCOVERING =		0x0013

MGMT_STATUS_SUCCESS		= 0x00
MGMT_STATUS_UNKNOWN_COMMAND	= 0x01
MGMT_STATUS_NOT_CONNECTED	= 0x02
MGMT_STATUS_FAILED		= 0x03
MGMT_STATUS_CONNECT_FAILED	= 0x04
MGMT_STATUS_AUTH_FAILED		= 0x05
MGMT_STATUS_NOT_PAIRED		= 0x06
MGMT_STATUS_NO_RESOURCES	= 0x07
MGMT_STATUS_TIMEOUT		= 0x08
MGMT_STATUS_ALREADY_CONNECTED	= 0x09
MGMT_STATUS_BUSY		= 0x0a
MGMT_STATUS_REJECTED		= 0x0b
MGMT_STATUS_NOT_SUPPORTED	= 0x0c
MGMT_STATUS_INVALID_PARAMS	= 0x0d
MGMT_STATUS_DISCONNECTED	= 0x0e
MGMT_STATUS_NOT_POWERED		= 0x0f
MGMT_STATUS_CANCELLED		= 0x10
MGMT_STATUS_INVALID_INDEX	= 0x11
MGMT_STATUS_RFKILLED		= 0x12
MGMT_STATUS_ALREADY_PAIRED	= 0x13
MGMT_STATUS_PERMISSION_DENIED	= 0x14

EIR_TYPE_FLAGS                = 0x01
EIR_TYPE_SHORT_NAME           = 0x08
EIR_TYPE_COMPLETE_NAME        = 0x09
EIR_TYPE_MANUFACTURER_DATA    = 0xFF




'''

struct mgmt_addr_info {
        bdaddr_t bdaddr;
        uint8_t type;
} __packed;

struct mgmt_ev_cmd_complete {
	uint16_t opcode;
	uint8_t status;
	uint8_t data[0];
} __packed;

struct mgmt_ev_cmd_status {
	uint16_t opcode;
	uint8_t status;
} __packed;

struct mgmt_ev_controller_error {
	uint8_t error_code;
} __packed;


struct mgmt_ev_class_of_dev_changed {
	uint8_t dev_class[3];
} __packed;

struct mgmt_ev_local_name_changed {
	uint8_t name[MGMT_MAX_NAME_LENGTH];
	uint8_t short_name[MGMT_MAX_SHORT_NAME_LENGTH];
} __packed;

struct mgmt_ev_new_link_key {
	uint8_t store_hint;
	struct mgmt_link_key_info key;
} __packed;

struct mgmt_ev_new_long_term_key {
	uint8_t store_hint;
	struct mgmt_ltk_info key;
} __packed;

struct mgmt_ev_device_connected {
	struct mgmt_addr_info addr;
	uint32_t flags;
	uint16_t eir_len;
	uint8_t eir[0];
} __packed;

MGMT_DEV_DISCONN_UNKNOWN =	0x00
MGMT_DEV_DISCONN_TIMEOUT =	0x01
MGMT_DEV_DISCONN_LOCAL_HOST =	0x02
MGMT_DEV_DISCONN_REMOTE =		0x03

struct mgmt_ev_device_disconnected {
	struct mgmt_addr_info addr;
	uint8_t reason;
} __packed;

struct mgmt_ev_connect_failed {
	struct mgmt_addr_info addr;
	uint8_t status;
} __packed;

struct mgmt_ev_pin_code_request {
	struct mgmt_addr_info addr;
	uint8_t secure;
} __packed;

struct mgmt_ev_user_confirm_request {
	struct mgmt_addr_info addr;
	uint8_t confirm_hint;
	uint32_t value;
} __packed;

struct mgmt_ev_user_passkey_request {
	struct mgmt_addr_info addr;
} __packed;

struct mgmt_ev_auth_failed {
	struct mgmt_addr_info addr;
	uint8_t status;
} __packed;

MGMT_DEV_FOUND_CONFIRM_NAME =	0x01
MGMT_DEV_FOUND_LEGACY_PAIRING =	0x02
MGMT_DEV_FOUND_NOT_CONNECTABLE =	0x04

struct mgmt_ev_device_found {
	struct mgmt_addr_info addr;
	int8_t rssi;
	uint32_t flags;
	uint16_t eir_len;
	uint8_t eir[0];
} __packed;

struct mgmt_ev_discovering {
	uint8_t type;
	uint8_t discovering;
} __packed;

'''



MGMT_INDEX_NONE = 0xFFFF


BDADDR_BREDR =           0x00
BDADDR_LE_PUBLIC =       0x01
BDADDR_LE_RANDOM =       0x02

SCAN_TYPE_BREDR = (1 << BDADDR_BREDR)
SCAN_TYPE_LE =  ((1 << BDADDR_LE_PUBLIC) | (1 << BDADDR_LE_RANDOM))
SCAN_TYPE_DUAL =  (SCAN_TYPE_BREDR | SCAN_TYPE_LE)




mgmt_index = MGMT_INDEX_NONE



def mgmt_open():
    s = btsocket(proto=BTPROTO_HCI)
    s.bind((-1, HCI_CHANNEL_CONTROL))

    return s




'''
struct mgmt_cp_start_discovery {
	uint8_t type;
} __packed;


struct mgmt_cp_stop_discovery {
	uint8_t type;
} __packed;

struct mgmt_cp_start_discovery cp;
	uint8_t op = MGMT_OP_START_DISCOVERY;
	uint8_t type = SCAN_TYPE_DUAL;
	int opt;
	uint16_t index;

	index = mgmt_index;
	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	cp.type = type;

	if (mgmt_send(mgmt, op, index, sizeof(cp), &cp, find_rsp,
							NULL, NULL) == 0) {
		error("Unable to send start_discovery cmd");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
--
unsigned int mgmt_send(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
				uint16_t length, const void *param,
				mgmt_request_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy)
{

	request = create_request(opcode, index, length, param,
					callback, user_data, destroy);


int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, uint8_t plen, void *param)
{
	uint8_t type = HCI_COMMAND_PKT;
	hci_command_hdr hc;
	struct iovec iv[3];
	int ivn;

	hc.opcode = htobs(cmd_opcode_pack(ogf, ocf));
	hc.plen= plen;

	iv[0].iov_base = &type;
	iv[0].iov_len  = 1;
	iv[1].iov_base = &hc;
	iv[1].iov_len  = HCI_COMMAND_HDR_SIZE;
	ivn = 2;

	if (plen) {
		iv[2].iov_base = param;
		iv[2].iov_len  = plen;
		ivn = 3;
	}

	while (writev(dd, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}


MGMT_HDR_SIZE =	6


static struct mgmt_request *create_request(uint16_t opcode, uint16_t index,
				uint16_t length, const void *param,
				mgmt_request_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy)
{
	struct mgmt_request *request;
	struct mgmt_hdr *hdr;

	if (!opcode)
		return NULL;

	if (length > 0 && !param)
		return NULL;

	request = new0(struct mgmt_request, 1);
	request->len = length + MGMT_HDR_SIZE;
	request->buf = malloc(request->len);
	if (!request->buf) {
		free(request);
		return NULL;
	}

	if (length > 0)
		memcpy(request->buf + MGMT_HDR_SIZE, param, length);

	hdr = request->buf;
	hdr->opcode = htobs(opcode);
	hdr->index = htobs(index);
	hdr->len = htobs(length);

	request->opcode = opcode;
	request->index = index;

	request->callback = callback;
	request->destroy = destroy;
	request->user_data = user_data;

	return request;
}

'''

def printpacket(pkt):
    for c in pkt:
        sys.stdout.write("%02x " % struct.unpack("B",c)[0])

'''
struct mgmt_hdr {
	uint16_t opcode;
	uint16_t index;
	uint16_t len;
} __packed;

'''
MGMT_HDR_SIZE = 6

def mgmt_send(sock, opcode, index, length, param):
    if index == MGMT_INDEX_NONE:
        index = 0
        
    print("opcode: %d, index: %d, length: %d") % (htobs(opcode), htobs(index), htobs(length))

    mgmt_request = struct.pack("=HHHs", htobs(opcode), htobs(index), htobs(length), param)
    printpacket(mgmt_request)
    print("")
    sock.send(mgmt_request)

def mgmt_start_discovery(sock):
    cmd_pkt = struct.pack("=B", SCAN_TYPE_DUAL)
    mgmt_send(sock, MGMT_OP_START_DISCOVERY, mgmt_index, 1, cmd_pkt)


def mgmt_get_event(sock):
    pkt = sock.recv(256)
    event, index, plen = struct.unpack("=HHH", pkt[:6])
#    printpacket(pkt)
    print("")
#    print("event: %d, index: %d, plen: %d") % (event, index, plen)
    return(event, pkt[6:])

'''
def parse_events(sock, loop_count=100):
    done = False
    results = []
    myFullList = {}
    for i in range(0, loop_count):
        pkt = sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])
        if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
		i =0
        elif event == bluez.EVT_NUM_COMP_PKTS:
                i =0 
        elif event == bluez.EVT_DISCONN_COMPLETE:
                i =0 
        elif event == bluez.EVT_CMD_STATUS:
            print "inquiry info"
        elif event == LE_META_EVENT:
            subevent, = struct.unpack("B", pkt[3])
            pkt = pkt[4:]
            if subevent == EVT_LE_CONN_COMPLETE:
                le_handle_connection_complete(pkt)
            elif subevent == EVT_LE_ADVERTISING_REPORT:
                print "advertising report"
                num_reports = struct.unpack("B", pkt[0])[0]
                report_pkt_offset = 0
                for j in range(0, num_reports):
		  company = returnstringpacket(pkt[report_pkt_offset + 15: report_pkt_offset + 17])
		  print "==============================================================================================================="
		  if (DEBUG == True):
			  print "\tfullpacket: ", printpacket(pkt)
			  print "\tCompany: ",company

		  if (company == "3301"):
			  print "\tCompany: ",company
			  print "\tMAC address: ", packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
			  mac = returnstringpacket(pkt[report_pkt_offset + 3: report_pkt_offset + 9])
			  myFullList["mac"] = mac
			  print "\tMAC Address string: ", returnstringpacket(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
			  tempString = returnstringpacket(pkt[report_pkt_offset + 23: report_pkt_offset + 25])
			  print "\tTemp: " , tempString 
			  temp = float(returnnumberpacket(pkt[report_pkt_offset + 23:report_pkt_offset + 25]))/10
			  print "\tTemp: " , temp
			  myFullList["temp"] = temp

			  print "\tHumidity: " ,printpacket(pkt[report_pkt_offset + 25:report_pkt_offset + 27])
			  humidity = float(returnnumberpacket(pkt[report_pkt_offset + 25:report_pkt_offset + 27]))/10
			  print "\tHumidity: " ,humidity 
			  myFullList["humidity"] = humidity 

'''

class mgmt_ev_device_found:
    def __init__(self, pkt):
        self.addr_info = pkt[:7]

        self.rssi, self.flags, self.eir_len = struct.unpack('=bIH', pkt[7:14])
        self.eir_data = pkt[14:]

    def _find_pdu(self, pdu_findtype, pdu_handler):
        results = []
        parsed = 0

        while parsed + 2 < self.eir_len:
            pdu_len = struct.unpack('=B', eir_data[parsed])[0]
            if pdu_len == 0:
                break
        
            pdu_type = struct.unpack('=B', eir_data[parsed + 1])[0]

            if pdu_type == pdu_find_type:
                results += [pdu_handler(eir_data[parsed + 2:parsed + 2 + pdu_len])]

            parsed = parsed + pdu_len + 1

        return manu_pdus

    def get_manufacturer_data(self):
        # There can be more than one manufacturer PDU in a single advertisement - bluemaestro tempo has two
        manu_pdus = []
        parsed = 0

        while parsed + 2 < self.eir_len:
            pdu_len = struct.unpack('=B', eir_data[parsed])[0]
            if pdu_len == 0:
                break
        
            pdu_type = struct.unpack('=B', eir_data[parsed + 1])[0]

            if pdu_type == EIR_TYPE_MANUFACTURER_DATA:
                id, data = struct.unpack('=Hs', eir_data[parsed + 2:parsed + 2 + pdu_len])
                manu_pdus += {
                    'id': id,
                    'data' : data
                    }

            parsed = parsed + pdu_len + 1

        return manu_pdus

    def _manufacturer_data_handler(pdu_data):
        id, data = struct.unpack('=Hs', pdu_data)
        return {
            'id': id,
            'data' : data
            }

    def get_manufacturer_data2(self):
        # There can be more than one manufacturer PDU in a single advertisement - bluemaestro tempo has two
        return self._find_pdu(EIR_TYPE_MANUFACTURER_DATA, _manufacturer_data_handler)

    def _name_handler(pdu_data):
        return pdu_data

    def get_name(self):
        # Should look for EIR_TYPE_COMPLETE_NAME as well
        return self._find_pdu(EIR_TYPE_SHORT_NAME, _name_handler)

class mgmt_ev_cmd_status:
    def __init__(self, pkt):
        self.opcode, self.status = struct.unpack('=Hb', pkt[0:3])

'''
        if (ev->addr.type != BDADDR_BREDR)
                        print("AD flags 0x%02x ",
eir_get_flags(ev->eir, eir_len));

                if (manuf == 0x0133)
                  dump_tempo(ev->eir, eir_len);
        }
'''

def ba2str(addr):
    addr_reversed = addr[5] + addr[4] + addr[3] + addr[2] + addr[1] + addr[0]
    return "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X" % struct.unpack_from('=BBBBBB', addr_reversed)

def parse_eir_data(eir_data, eir_len):
    parsed = 0

    while parsed + 2 < eir_len:
        pdu_len = struct.unpack('=B', eir_data[parsed])[0]
        if pdu_len == 0:
            break
        
        pdu_type = struct.unpack('=B', eir_data[parsed + 1])[0]

        if pdu_type == EIR_TYPE_FLAGS:
            print("Flags: %.2x") % struct.unpack('=B', eir_data[parsed + 2])[0]
        elif pdu_type == EIR_TYPE_SHORT_NAME or pdu_type == EIR_TYPE_COMPLETE_NAME:
            print("Name: %s") % eir_data[parsed + 2:parsed + 2 + pdu_len]
        elif pdu_type == EIR_TYPE_MANUFACTURER_DATA:
            print("Manufacturer %.4X, length %d") % (struct.unpack('=H', eir_data[parsed + 2:parsed + 4])[0], pdu_len)
        else:
            print("PDU type %.2X length %d") % (pdu_type, pdu_len)
        
        parsed = parsed + pdu_len + 1


class tempo_data:
    def __init__(self, data):
        self.version = struct.unpack('=B', data[0])[0]
        if self.version != 15:
            return  #Should throw an exception

        self.battery, self.time_interval, self.stored_logcount, self.temp, self.humidity, self.dewpoint, self.mode, self.breach_count = struct.unpack('>BHHHHHBB', data[1:])
        self.battery = self.battery / 255
        self.temp /= 10
        self.humidity /= 10
    
    def pdu2(self, data):
        (self.temp_high,
         self.humidity_high,
         self.temp_low, 
         self.humidity_low,
         self.temp_24high,
         self.humidity_24_high,
         self.temp_24_low,
         self.humidity_24_low) = struct.unpack('>HHHHHHHH', data)
     
        
        
        

def main():
    sock = mgmt_open()
    mgmt_start_discovery(sock)

    event, data = mgmt_get_event(sock)

    if event == MGMT_EV_CMD_STATUS:
        cmd_status = mgmt_ev_cmd_status(data)
        if cmd_status.status != MGMT_STATUS_SUCCESS:
            if cmd_status.status == MGMT_STATUS_PERMISSION_DENIED:
                print("Acccess denied - are you root?")
            elif cmd_status.status != MGMT_STATUS_SUCCESS:
                print("Command failed %.2X") % cmd_status.status
            return
        event, data = mgmt_get_event(sock)
    
    if event == MGMT_EV_CMD_COMPLETE:
        event, data = mgmt_get_event(sock)
        if event == MGMT_EV_DISCOVERING:
            print("Discovering...")
            event, data = mgmt_get_event(sock)
            while event == MGMT_EV_DEVICE_FOUND:
                found_data = mgmt_ev_device_found(data)
                mfg_data = found_data.get_manufacturer_data()
#                for 
                print("rssi: %d, data len %d") % (found_data.rssi, found_data.eir_len)
                print("address %s") % ba2str(found_data.addr_info)
                parse_eir_data(found_data.eir_data, found_data.eir_len)
                event, data = mgmt_get_event(sock)

    print("Event: %.2X") % event

main()

            

