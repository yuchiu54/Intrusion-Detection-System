from datetime import datetime

class Log:
    def __init__(self, level='normal', content=None, time=None, ip=None):
        self.level = level
        self.content = content
        self.time = time
        self.ip = ip
        self.result = ''

    def form_result(self):
        output = ''
        time = datetime.fromtimestamp(self.time)
        output += time.strftime('%m/%d/%y %H:%M:%S') + ' '
        output += self.level + ' '
        output += self.ip + ' '
        output += self.content + '\n'
        self.result = output

    def wrlog(self, filename):
        self.form_result()
        with open(filename, 'a') as f:
            f.write(self.result)
            print('Write to file sucessfully')
            f.close()
