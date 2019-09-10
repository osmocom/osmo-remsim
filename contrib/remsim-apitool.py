#!/usr/bin/env python3

import sys
import argparse
import requests

version = "0.1"

#access rest
def build_url(suffix):
    BASE_PATH = "/api/backend/v1"
    return ("http://" + server_host + ":" + server_port + BASE_PATH + suffix)

def rest_get(suffix):
    if verbose:
        print("GET "+ build_url(suffix))
    try:
        resp = requests.get(build_url(suffix))
    except:
        print("REST GET failed")
        return
    if resp.ok:
        try:
            js = resp.json()
            print("%s: %s" % (suffix, js))
        except:
            return
    else:
        return None

def rest_post(suffix, js = None):
    if verbose:
        print("POST "+ build_url(suffix)+ str(js))
    resp = requests.post(build_url(suffix), json=js)
    if not resp.ok:
        print("post failed")

def rest_delete(suffix):
    if verbose:
        print("DELETE "+ build_url(suffix))
    resp = requests.delete(build_url(suffix))
    if not resp.ok:
        print("delete failed")

#rest calls
def slotmap_create(bank_id, bank_slot, client_id, client_slot):
    js = {
        'bank': {'bankId': int(bank_id), 'slotNr': int(bank_slot)},
        'client': {'clientId': int(client_id), 'slotNr': int(client_slot)},
        }
    return rest_post('/slotmaps', js)

def slotmap_delete(bank_id, bank_slot):
    slotmap_id = bank_id * 65536 + bank_slot
    return rest_delete("/slotmaps/%u"%slotmap_id)

def reset_global():
    return rest_post('/global-reset')

def main(argv):
    global server_port, server_host, verbose

    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host",    help="host to connect to",                        default="127.0.0.1")
    parser.add_argument("-p", "--port",    help="port to connect to",                        default="9997")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="count", default=0)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--reset",          help="remove all mappings  (POST /global-reset)", action="store_true")
    group.add_argument("-c", "--show-clients",   help="show clients         (GET /clients)",nargs='?',const="all",default=None)
    group.add_argument("-b", "--show-banks",     help="show banks           (GET /banks)",nargs='?',const="all",default=None)
    group.add_argument("-s", "--show-slotmaps",  help="show slotmaps        (GET /slotmaps)",nargs='?',const="all",default=None)
    group.add_argument("-m", "--create-slotmap", help="create new slotmap   (POST /slotmaps)", type=int, nargs=4,metavar=('bank_id', 'bank_slot','client_id','client_slot'))
    group.add_argument("-d", "--delete-slotmap", help="delete slotmapping   (DELETE /slotmaps/<id>)", type=int, nargs=2, metavar=('bank_id','bank_slot'))
    group.add_argument("-a", "--show-all",       help="show all (default if no argument given)", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        print("verbosity = ", args.verbose)

    server_host = args.host
    server_port = args.port
    verbose = args.verbose

    if args.reset:
        reset_global()
        return
    if args.show_clients:
        if args.show_clients == "all":
            rest_get("/clients")
        else:
            rest_get("/clients/" + str(args.show_clients))
        return
    if args.show_banks:
        if args.show_banks == "all":
            rest_get("/banks")
        else:
            rest_get("/banks/" + str(args.show_banks))
        return
    if args.show_slotmaps:
        if args.show_slotmaps == "all":
            rest_get("/slotmaps")
        else:
            rest_get("/slotmaps/" + str(args.show_slotmaps))
        return
    if args.create_slotmap:
        slotmap_create(args.create_slotmap[0],args.create_slotmap[1],args.create_slotmap[2],args.create_slotmap[3])
        return
    if args.delete_slotmap:
        slotmap_delete(args.delete_slotmap[0],args.delete_slotmap[1])
        return
    rest_get("/clients")
    rest_get("/banks")
    rest_get("/slotmaps")

if __name__ == "__main__":
    main(sys.argv)

