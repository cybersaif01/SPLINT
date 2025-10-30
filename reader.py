LOG_FILE = "/var/log/auth.log"

def read_last_lines(file_path,num_of_lines=10):
	with open(file_path, 'r') as file:
		lines = file.readlines()
		return lines[-num_of_lines:]
		
if __name__ == "__main__":
	lines = read_last_lines(LOG_FILE,10)
	for line in lines:
		print(line.strip())
