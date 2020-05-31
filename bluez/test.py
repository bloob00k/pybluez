import time
from mgmt import *
import tempo
        
def get_tempo_data(mfg_data):
    pdu1 = None
    pdu2 = None

    for record in mfg_data:
        if record['id'] == tempo.BLUEMAESTRO_MFR_CODE:
            if pdu1 is None:
                pdu1 = record['data']
            else:
                pdu2 = record['data']
                break

    if pdu1 is not None:
        return tempo.tempo_data(pdu1, pdu2)

    return None
        

def discover_devices(sock):
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
                device = mgmt_ev_device_found(data)
                mfg_data = device.get_manufacturer_data()
                tempo_data = get_tempo_data(mfg_data)
                if tempo_data:
                    print("Address: %s; Name: %s; Flags: %X") % (ba2str(device.addr_info), device.get_name()[0], device.flags)
                    print("rssi: %d; battery: %d") % (device.rssi, tempo_data.battery)
                    print("Temperature: %.1f") % tempo_data.temp
                    print("Humidity: %.1f") % tempo_data.humidity
                else:
                    parse_eir_data(device.eir_data, device.eir_len)
                event, data = mgmt_get_event(sock)

    if event != MGMT_EV_DISCOVERING:
        print("Unexpected event: %.2X") % event
    else:
        ev_discovering = mgmt_ev_discovering(data)
        if not ev_discovering.discovering:
            print("Discovery complete")
        else:
            print("Unexpected Discover Enabled event")
    

def main():
    btsock = mgmt_open()

    while True:
        discover_devices(btsock)
        time.sleep(60)

main()

            

