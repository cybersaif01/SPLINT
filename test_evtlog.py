import win32evtlog

server = 'localhost'
log_type = 'Security'
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

hand = win32evtlog.OpenEventLog(server, log_type)
events = win32evtlog.ReadEventLog(hand, flags, 0)

count = 0
for event in events:
    count += 1
    print(f"Event #{event.RecordNumber} | Source: {event.SourceName}")
    if count >= 5:
        break

print(f"\nTotal read: {count} events")
