import pyudev
import platform
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

def get_device_info(device):
    """Extracts a user-friendly name for a USB device."""
    # Try to get model and vendor names for a readable description
    vendor = device.get('ID_VENDOR_FROM_DATABASE', 'Unknown Vendor')
    model = device.get('ID_MODEL_FROM_DATABASE', 'Unknown Model')
    
    if vendor != 'Unknown Vendor' or model != 'Unknown Model':
        return f"{vendor} {model}"
    
    # Fallback to a more generic name if the database names aren't available
    return device.get('ID_MODEL', 'Generic USB Device')

def monitor_usb():
    """
    Monitors for USB device connection and disconnection events using pyudev.
    This function is a generator, yielding a dictionary for each event.
    """
    # First, check if the system is Linux, as pyudev is Linux-specific
    if platform.system() != "Linux":
        print(f"{Fore.RED}[USB Monitor] Error: This monitor only works on Linux.")
        return # Exit the function gracefully if not on Linux

    try:
        # Set up the pyudev context and monitor
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        # Filter for events related to the 'usb' subsystem
        monitor.filter_by(subsystem='usb')
        
        print(f"{Fore.CYAN}[+] USB monitoring service started (using pyudev). Waiting for events...{Style.RESET_ALL}")

        # Continuously listen for events
        for device in iter(monitor.poll, None):
            # We are interested in 'add' (connect) and 'remove' (disconnect) actions
            if device.action == "add" and "ID_MODEL" in device:
                device_info = get_device_info(device)
                print(f"{Fore.YELLOW}[USB Event] Device Connected: {device_info}")
                yield {'event': 'connected', 'device': device_info}
            
            elif device.action == "remove" and "ID_MODEL" in device:
                device_info = get_device_info(device)
                print(f"{Fore.YELLOW}[USB Event] Device Disconnected: {device_info}")
                yield {'event': 'disconnected', 'device': device_info}

    except ImportError:
        print(f"{Fore.RED}[USB Monitor] Error: 'pyudev' library not found.")
        print(f"{Fore.YELLOW}  └── Please install it on your host machine with: sudo apt-get install python3-pyudev")
    except Exception as e:
        print(f"{Fore.RED}[USB Monitor] A critical error occurred: {e}")