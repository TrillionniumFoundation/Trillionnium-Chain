import os,signal,time,json,sys
read,write=os.pipe()
pid=os.fork()
if pid==0:
 os.close(read)
 def stop(*_):
  print('adopted-terminal-tail'); sys.exit(31)
 signal.signal(signal.SIGTERM,stop)
 os.write(write,b'1'); os.close(write); time.sleep(90)
else:
 os.close(write); os.read(read,1); os.close(read)
 print(json.dumps({'pgid':os.getpgrp(),'child':pid}))
 os._exit(0)
