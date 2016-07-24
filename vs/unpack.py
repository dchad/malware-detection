##############################################################
# Python script to attempt automatic unpacking/decrypting of #
# malware samples using WinAppDbg.                           #
#                                                            #
# unpack.py v2016.01.25                                      #
# http://malwaremusings.com/scripts/unpack.py                #
##############################################################

import sys
import traceback
import winappdbg
import time
import struct
import ctypes


# Log file which we log info to
logfile = None

class MyEventHandler(winappdbg.EventHandler):

###
# A. Declaring variables
###

  # A.1 used to keep track of allocated executable memory
  allocedmem = {}

  # A.2 used to indicate that we've found the entry point
  entrypt = 0x00000000

  #
  # variables used to find and disassemble unpacking loop
  #

  # A.3 used to indicate that we're single stepping
  tracing = -1

  # A.4 remember the last two eip values
  lasteip = [0x00000000,0x00000000]

  # A.5 lowest eip address we see
  lowesteip = 0xffffffff

  # A.6 highest eip address we see
  highesteip = 0x00000000

  # A.7 list of addresses which we've disassembled
  disasmd = []

  # A.8 keeps track of addresses and instructions
  #     that write to the allocated memory block(s)
  writeaddrs = {}

  #
  # variables used to keep track of created processes
  #

  # A.9 keeps track of created processes to map
  #     hProcess from WriteProcessMemory() back to
  #     process name
  createdprocesses = {}

  # A.10 keeps track of processes that were created
  #      with the CREATE_SUSPENDED flag set
  createsuspended = {}

  #
  # variables used for logging
  #

  # A.11 used to keep a log of events
  eventlog = []


###
# B. Class methods (functions)
###

  ### B.1
  # get_funcargs(event)
  #     query winappdbg to get the function arguments
  #
  #     return a tuple consisting of the return address
  #     and a sub-tuple of function arguments
  ###

  def get_funcargs(self,event):
    h = event.hook
    t = event.get_thread()
    tid = event.get_tid()

    return (t.get_pc(),h.get_params(tid))


  ### B.2
  # guarded_read(d,t,addr,size)
  #     read memory after checking for, and if necessary,
  #     disabling memory breakpoints
  #
  #     returns a string of data
  ###

  def guarded_read(self,d,t,addr,size):
    # keep track of breakpoints that we disabled
    # so that we can enable them again after we've
    # finished
    reenablebps = []

    # initialise the variable to hold the read 
    # memory data
    data = ""

    # check that the requested size is sane
    if (size > 0):
      p = t.get_process()

      # check to see if the requested address falls within
      # any of the existing memory breakpoints by checking
      # if either the requested start address or end address
      # is covered by any breakpoint
      mem_bps = d.get_all_page_breakpoints()
      for (pid,pgbp) in mem_bps:
        (startaddr,endaddr) = pgbp.get_span()
        if (pid == p.get_pid()) and (pgbp.is_here(addr) or pgbp.is_here(addr + size - 1)):
          log("[D]   Memory read in guarded memory. Disabling breakpoint: %s" % pgbp)
          pgbp.disable(p,t)
          reenablebps.append(pgbp)

      # read the memory
      data = p.read(addr,size)

      # enable all of the breakpoints that we disabled
      if (len(reenablebps) > 0):
        for pgbp in reenablebps:
          log("[D]   Re-enabling breakpoint: %s" % pgbp)
          pgbp.enable(p,t)

    # return the read memory as a string
    return data


###
# C. API Hooks
###

  ### C.1
  # apiHooks: winappdbg defined hash of API calls to hook
  #
  #     Each entry is indexed by library name and is an array of 
  #     tuples consisting of API call name and number of args
  ###

  apiHooks = {
    "kernel32.dll":[
      ("VirtualAlloc",4),
      ("VirtualAllocEx",5),
      ("IsDebuggerPresent",0),
      ("CreateProcessA",10),
      ("CreateProcessW",10),
      ("WriteProcessMemory",5)
    ],
    "advapi32.dll":[
      ("CryptDecrypt",6)
    ],
    "wininet.dll":[
      ("InternetOpenA",5),
      ("InternetOpenW",5)
    ],
    "ntdll.dll":[
      ("RtlDecompressBuffer",6)
    ],
    "secur32.dll":[
      ("EncryptMessage",4),
      ("DecryptMessage",4)
    ]
  }


  ###
  # API hook callback functions
  #
  #     These are defined by winappdbg and consist of functions
  #     named pre_<apifuncname> and post_<apifuncname> which are
  #     called on entry to, and on exit from, the given API 
  #     function (<apifuncname>), respectively.
  ###

  # C.2
  # VirtualAlloc() hook(s)
  #

  def post_VirtualAllocEx(self,event,retval):
    try:
      # C.2.1 Get the return address and arguments

      (ra,(hProcess,lpAddress,dwSize,flAllocationType,flProtect)) = self.get_funcargs(event)

      # Get an instance to the debugger which triggered the event
      # and also the process id and thread id of the process to which 
      # the event pertains

      d = event.debug
      pid = event.get_pid()
      tid = event.get_tid()

      # Log the fact that we've seen a VirtualAllocEx() call

      log("[*] <%d:%d> 0x%x: VirtualAllocEx(0x%x,0x%x,0x%x (%d),0x%x,0x%03x) = 0x%x" % (pid,tid,ra,hProcess,lpAddress,dwSize,dwSize,flAllocationType,flProtect,retval))

      # C.2.2 All the memory protection bits which include EXECUTE
      # permission use bits 4 - 7, which is nicely matched 
      # by masking (ANDing) it with 0xf0 and checking for a 
      # non-zero result

      if (flProtect & 0x0f0):
        log("[-]   Request for EXECUTEable memory")

        # We can only set page guards on our own process
        # otherwise page guard exception will occur in 
        # system code when this process attempts to write 
        # to the allocated memory.
        # This causes ZwWriteVirtualMemory() to fail

        # We can, however, set a page guard on it when 
        # this process creates the remote thread, as it 
        # will have presumably stopped writing to the 
        # other process' memory at that point.

        # C.2.2.1 Check that this VirtualAllocEx() call is for
        # the current process (hProcess == -1), and if
        # so, ask the winappdbg debugger instance to 
        # create a page guard on the memory region.
        # Also add information about the allocated region
        # to our allocedmem hash, indexed by pid and 
        # base address.

        if (hProcess == 0xffffffff):
          d.watch_buffer(pid,retval,dwSize - 1,self.guard_page_exemem)
          self.allocedmem[(pid,retval)] = dwSize

      # C.2.3 Create a JSON event log entry

      self.eventlog.append({
        "time": time.time(),
        "name": "VirtualAllocEx",
        "type": "Win32 API",
        "pid": pid,
        "tid": tid,
        "addr": ra,
        "args": {
          "hProcess": hProcess,
          "lpAddress": lpAddress,
          "dwSize": dwSize,
          "flAllocationType": flAllocationType,
          "flProtect": flProtect
        },
        "ret": retval
      })
    except:
      traceback.print_exc()
      raise


  def post_VirtualAlloc(self,event,retval):
    try:
      # C.2.4 Get the return address and arguments

      (ra,(lpAddress,dwSize,flAllocationType,flProtect)) = self.get_funcargs(event)

      # Get an instance to the debugger which triggered the event
      # and also the process id and thread id of the process to which 
      # the event pertains

      d = event.debug
      pid = event.get_pid()
      tid = event.get_tid()

      # Log the fact that we've seen a VirtualAlloc() call
      # This is so that we get the address in the debuggee code from which it was called
      # where as if we just let the VirtualAllocEx() hook log it, the address from 
      # which it was called is inside the VirtualAlloc() code in kernel32.dll

      log("[*] <%d:%d> 0x%x: VirtualAlloc(0x%x,0x%x (%d),0x%x,0x%03x) = 0x%x" % (pid,tid,ra,lpAddress,dwSize,dwSize,flAllocationType,flProtect,retval))

      # C.2.5 Create a JSON event log entry

      self.eventlog.append({
        "time": time.time(),
        "name": "VirtualAlloc",
        "type": "Win32 API",
        "pid": pid,
        "tid": tid,
        "addr": ra,
        "args": {
          "lpAddress": lpAddress,
          "dwSize": dwSize,
          "flAllocationType": flAllocationType,
          "flProtect": flProtect
        },
        "ret": retval
      })
    except:
      traceback.print_exc()
      raise


  # C.3
  # CryptDecrypt() hook(s)
  #

  def pre_CryptDecrypt(self,event,*args):
    # C.3.1 Get the return address and arguments

    (ra,hKey,hHash,Final,dwFlags,pbData,pdwDataLen) = (args[0],args[1],args[2],args[3],args[4],args[5],args[6])

    # C.3.2 Get a Process object and dereference the pdwDataLen argument to read the buffer size

    p = event.get_process()
    buffsize = p.read_uint(pdwDataLen)

    # C.3.3 Save a copy of the encrypted data

    filename = "%s.memblk0x%x.enc" % (sys.argv[1],pbData)
    log("[-]   Dumping %d bytes of encrypted memory at 0x%x to %s" % (buffsize,pbData,filename))
    databuff = open(filename,"wb")
    databuff.write(p.read(pbData,buffsize));
    databuff.close()


  def post_CryptDecrypt(self,event,retval):
    # C.3.4 Get the return address and arguments

    (ra,(hKey,hHash,Final,dwFlags,pbData,pdwDataLen)) = self.get_funcargs(event)

    # Get a Process object, and dereference the pdwDataLen argument

    p = event.get_process()
    buffsize = p.read_uint(pdwDataLen)

    pid = event.get_pid()
    tid = event.get_tid()

    log("[*] <%d:%d> 0x%x: CryptDecrypt(0x%x,0x%x,0x%x,0x%x,0x%x,0x%x (%d)) = %d" % (pid,tid,ra,hKey,hHash,Final,dwFlags,pbData,buffsize,buffsize,retval))

    # C.3.5 Save a copy of the decrypted data

    filename_enc = "%s.memblk0x%x.enc" % (sys.argv[1],pbData)
    filename = "%s.memblk0x%x.dec" % (sys.argv[1],pbData)
    log("[-]   Dumping %d bytes of decrypted memory at 0x%x to %s" % (buffsize,pbData,filename))
    databuff = open(filename,"wb")
    databuff.write(p.read(pbData,buffsize))
    databuff.close()

    # C.3.6 Create a JSON event log entry

    pid = event.get_pid()
    tid = event.get_tid()
    self.eventlog.append({
      "time": time.time(),
      "name": "CryptDecrypt",
      "type": "Win32 API",
      "pid": pid,
      "tid": tid,
      "addr": ra,
      "args": {
        "hKey": hKey,
        "hHash": hHash,
        "Final": Final,
        "dwFlags": dwFlags,
        "pbData": pdwDataLen
      },
      "ret": retval,
      "info": {
        "filename_enc": filename_enc,
        "filename_dec": filename
      }
    })


  # C.4
  # RtlDecompressBuffer() hook(s)
  #

  def pre_RtlDecompressBuffer(self,event,*args):
    try:
      # C.4.1 Get the return address and arguments

      (ra,CompressionFormat,UncompressedBuffer,UncompressedBufferSize,CompressedBuffer,CompressedBufferSize,FinalUncompressedSize) = (args[0],args[1],args[2],args[3],args[4],args[5],args[6])

      p = event.get_process()

      # C.4.2 Save a copy of the compressed data

      filename = "%s.memblk0x%x.comp" % (sys.argv[1],CompressedBuffer)
      log("[-]   Dumping %d bytes of compressed memory at 0x%x to %s" % (CompressedBufferSize,CompressedBuffer,filename))
      databuff = open(filename,"wb")
      databuff.write(p.read(CompressedBuffer,CompressedBufferSize));
      databuff.close()
    except:
      traceback.print_exc()
      raise
      

  def post_RtlDecompressBuffer(self,event,retval):
    try:
      # C.4.3 Get the return address and arguments

      (ra,(CompressionFormat,UncompressedBuffer,UncompressedBufferSize,CompressedBuffer,CompressedBufferSize,FinalUncompressedSize)) = self.get_funcargs(event)

      pid = event.get_pid()
      tid = event.get_tid()

      log("[*] <%d:%d> 0x%x: RtlDecompressBuffer(0x%x,0x%x,0x%x,0x%x,0x%x,0x%x): %d" % (pid,tid,ra,CompressionFormat,UncompressedBuffer,UncompressedBufferSize,CompressedBuffer,CompressedBufferSize,FinalUncompressedSize,retval))

      # Get a Process object, and dereference the FinalUncompressedSize argument

      p = event.get_process()
      buffsize = p.read_uint(FinalUncompressedSize)

      # C.4.4 save a copy of the decompressed data

      filename_comp = "%s.memblk0x%x.comp" % (sys.argv[1],CompressedBuffer)
      filename = "%s.memblk0x%x.decomp" % (sys.argv[1],UncompressedBuffer)
      log("[-]   Dumping %d bytes of decompressed memory at 0x%x to %s" % (buffsize,UncompressedBuffer,filename))
      databuff = open(filename,"wb")
      databuff.write(p.read(UncompressedBuffer,buffsize))
      databuff.close()

      # C.4.5 Create a JSON event log entry

      self.eventlog.append({
        "time": time.time(),
        "name": "RtlDecompressBuffer",
        "type": "Win32 API",
        "pid": pid,
        "tid": tid,
        "addr": ra,
        "args": {
          "CompressionFormat": CompressionFormat,
          "UncompressedBuffer": UncompressedBuffer,
          "UncompressedBufferSize": UncompressedBufferSize,
          "CompressedBuffer": CompressedBuffer,
          "CompressedBufferSize": CompressedBufferSize,
          "FinalUncompressedSize": FinalUncompressedSize
        },
        "ret": retval,
        "info": {
          "filename_comp": filename_comp,
          "filename_decomp": filename
        }
      })
    except:
      traceback.print_exc()
      raise


  # C.5
  # CreateProcess() hook(s)
  #

  def post_CreateProcess(self,event,retval,fUnicode):
    try:
      # C.5.1 Get the return address and arguments

      (ra,(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation)) = self.get_funcargs(event)

      p = event.get_process()
      t = event.get_thread()

      pid = event.get_pid()
      tid = event.get_tid()

      # C.5.2 Dereference arguments
      # Use the Process object to dereference the lpApplicationName and lpCommandLine arguments
      # as either ASCII or WCHAR depending on the fUnicode argument
      # (and hence whether we were called from post_CreateProcessA() or post_CreateProcessW() respectively

      szApplicationName = p.peek_string(lpApplicationName,fUnicode)
      szCommandLine = p.peek_string(lpCommandLine,fUnicode)

      # If the lpProcessInformation argument is a valid pointer...

      if (lpProcessInformation):
        # ... dereference it to get the ProcessInformation structure

        d = event.debug
        ProcessInformation = self.guarded_read(d,t,lpProcessInformation,16)

        # Extract the various fields from the ProcessInformation structure

        hProcess = struct.unpack("<L",ProcessInformation[0:4])[0]
        hThread  = struct.unpack("<L",ProcessInformation[4:8])[0]
        dwProcessId = struct.unpack("<L",ProcessInformation[8:12])[0]
        dwThreadId = struct.unpack("<L",ProcessInformation[12:16])[0]
      else:
        log("[E]   lpProcessInformation is null")

      log("[*] <%d:%d> 0x%x: CreateProcess(\"%s\",\"%s\",0x%x): %d (0x%x, 0x%x, <%d:%d>)" % (pid,tid,ra,szApplicationName,szCommandLine,dwCreationFlags,retval,hProcess,hThread,dwProcessId,dwThreadId))

      # C.5.3 Check if the process is being created in a suspended state (CREATE_SUSPENDED flag)...

      if (dwCreationFlags & 0x4):
        # ... hook the ResumeThread() API call
        # so that we are notified when it is resumed

        d = event.debug
        stat = d.hook_function(pid,"ResumeThread",preCB = self.hook_createsuspendedresume,paramCount = 1)
        self.createsuspended[(pid,hThread)] = dwProcessId
        log("[-]   CREATE_SUSPENDED. Hooking ResumeThread() (%d)" % stat)

      # C.5.4 Keep track of processes that were created, so we know which 
      # process any WriteProcessMemory() calls are writing to

      self.createdprocesses[hProcess] = {
        "time": time.time(),
        "ppid": pid,
        "ptid": tid,
        "paddr": ra,
        "ApplicationName":szApplicationName,
        "CommandLine": szCommandLine,
        "CreationFlags": dwCreationFlags,
        "hProcess": hProcess,
        "hThread": hThread,
        "ProcessId": dwProcessId,
        "ThreadId": dwThreadId
      }

      # C.5.5 Create a JSON event log entry

      self.eventlog.append({
        "time": time.time(),
        "name": "CreateProcess",
        "type": "Win32 API",
        "pid": pid,
        "tid": tid,
        "addr": ra,
        "args": {
          "ApplicationName":szApplicationName,
          "CommandLine": szCommandLine,
          "CreationFlags": dwCreationFlags,
          "hProcess": hProcess,
          "hThread": hThread,
          "ProcessId": dwProcessId,
          "ThreadId": dwThreadId
        },
        "info": {
          "fUnicode":fUnicode
        },
        "ret": retval
      })
    except:
      traceback.print_exc()
      raise


  # C.5.6 post_CreateProcessA() and post_CreateProcessW()
  # Actual hook call-back function called by WinAppDbg
  # To save duplicating code between this and post_CreateProcessW()
  # both of them call post_CreateProcess() with a parameter, fUnicode, 
  # which specifies whether the strings are ASCII (CreateProcessA()) 
  # or WCHAR (CreateProcessW())

  def post_CreateProcessA(self,event,retval):
    self.post_CreateProcess(event,retval,False)


  def post_CreateProcessW(self,event,retval):
    self.post_CreateProcess(event,retval,True)


  # hook_createsuspendedresume() is a call-back function called when
  # ResumeThread() is call by a process which has created a suspended
  # process

  def hook_createsuspendedresume(self,event,*args):
    # C.5.7 Get the return address and arguments

    (ra,(hThread,)) = self.get_funcargs(event)

    pid = event.get_pid()
    tid = event.get_tid()

    log("[*] <%d:%d> 0x%x: ResumeThread(0x%x)" % (pid,tid,ra,hThread))

    # C.5.8 Find the process id of the resumed process

    if ((pid,hThread) in self.createsuspended):
      pidresumed = self.createsuspended[(pid,hThread)]
      log("[-]   New suspended process (pid %d) resumed" % pidresumed)


  # C.6
  # WriteProcessMemory() hook(s)
  #

  def post_WriteProcessMemory(self,event,retval):
    # C.6.1 Get the return address and arguments

    try:
      (ra,(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten)) = self.get_funcargs(event)

      pid = event.get_pid()
      tid = event.get_tid()

      log("[*] <%d:%d> 0x%x: WriteProcessMemory(0x%x,0x%x,0x%x,0x%x,0x%x): %d" % (pid,tid,ra,hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten,retval))

      d = event.debug
      t = event.get_thread()

      # C.6.2 Dereference lpNumberOfBytesWritten to get the number of bytes written to the target process'
      #       address space

      if (lpNumberOfBytesWritten):
        NumberOfBytesWritten = struct.unpack("<L",self.guarded_read(d,t,lpNumberOfBytesWritten,4))[0]
      else:
        NumberOfBytesWritten = None

      # C.6.3 Get process information that was saved by CreateProcess() hook

      if (hProcess in self.createdprocesses):
        ProcessId = self.createdprocesses[hProcess]["ProcessId"]
        ApplicationName = self.createdprocesses[hProcess]["ApplicationName"]
        CommandLine = self.createdprocesses[hProcess]["CommandLine"]
      else:
        log("[W]   hProcess not in createdprocesses[]")
        ProcessId = None
        ApplicationName = None
        CommandLine = None

      d = event.debug
      t = event.get_thread()

      # C.6.4 Save a copy of the written memory

      pid = event.get_pid()
      tid = event.get_tid()
      filename = "%s.memblk0x%x-%d.wpm" % (sys.argv[1],lpBaseAddress,ProcessId)
      log("[-]   Dumping %d bytes of memory at %d:0x%x written to %d:0x%x to %s" % (nSize,pid,lpBuffer,ProcessId,lpBaseAddress,filename))
      databuff = open(filename,"wb")
      databuff.write(self.guarded_read(d,t,lpBuffer,nSize))
      databuff.close()

      # C.6.5 Create a JSON event log entry

      self.eventlog.append({
        "time": time.time(),
        "name": "WriteProcessMemory",
        "type": "Win32 API",
        "pid": pid,
        "tid": tid,
        "addr": ra,
        "args": {
          "hProcess": hProcess,
          "lpBaseAddress": lpBaseAddress,
          "lpBuffer": lpBuffer,
          "nSize": nSize,
          "lpNumberOfBytesWritten": lpNumberOfBytesWritten,
          "NumberOfBytesWritten": NumberOfBytesWritten
        },
        "ret": retval,
        "info": {
          "filename": filename,
          "targetprocesspid": ProcessId,
          "targetprocessname": ApplicationName,
          "targetprocesscmdline": CommandLine
        }
      })
    except:
      traceback.print_exc()
      raise


  # C.7
  # IsDebuggerPresent() hook(s)
  # (mainly added so that AutoIt compiled scripts would run, but also useful
  #  as an anti-anti-malware technique)
  #

  def post_IsDebuggerPresent(self,event,retval):
    # C.7.1 Get the return address and arguments

    (ra,noargs) = self.get_funcargs(event)

    pid = event.get_pid()
    tid = event.get_tid()

    log("[*] <%d:%d> 0x%x: IsDebuggerPresent(): 0x%x" % (pid,tid,ra,retval))
    log("[-]   Returning 0")

    # C.7.2 Changed the 'eax' register (return value) to '0' (no debugger present)
    #       just before we continue running the calling thread

    t = event.get_thread()
    t.set_register("Eax",0x0)

    # C.7.3 Create a JSON event log entry

    self.eventlog.append({
      "time": time.time(),
      "name": "IsDebuggerPresent",
      "type": "Win32 API",
      "pid": pid,
      "tid": tid,
      "addr": ra,
      "args": {},
      "ret": retval,
      "info": {}
    })


  # C.8
  # InternetOpen() hook(s)
  #

  def post_InternetOpen(self,event,retval,fUnicode):
    # C.8.1 Get the return address and arguments

    (ra,(lpszAgent,dwAccessType,lpszProxyName,lpszProxyBypass,dwFlags)) = self.get_funcargs(event)

    pid = event.get_pid()
    tid = event.get_tid()

    # C.8.2 Dereference arguments

    p = event.get_process()
    szAgent = p.peek_string(lpszAgent,fUnicode)
    szProxyName = p.peek_string(lpszProxyName,fUnicode)
    szProxyBypass = p.peek_string(lpszProxyBypass,fUnicode)

    log("[*] <%d:%d> 0x%x: InternetOpen(\"%s\",0x%x,\"%s\",\"%s\",0x%x) = 0x%x" % (pid,tid,ra,szAgent,dwAccessType,szProxyName,szProxyBypass,dwFlags,retval))

    # C.8.3 Create a JSON event log entry

    self.eventlog.append({
      "time": time.time(),
      "name": "InternetOpen",
      "type": "Win32 API",
      "pid": pid,
      "tid": tid,
      "addr": ra,
      "args": {},
      "ret": retval,
      "info": {}
    })


  def post_InternetOpenA(self,event,retval):
    self.post_InternetOpen(event,retval,False)


  def post_InternetOpenW(self,event,retval):
    self.post_InternetOpen(event,retval,True)


  def pre_EncryptMessage(self,event,*args):
    # C.?.1 Get the return address and arguments

    try:
      (ra,phContext,fQOP,pMessage,MessageSeqNo) = (args[0],args[1],args[2],args[3],args[4])

      pid = event.get_pid()
      tid = event.get_tid()

      # Right -- this is going to get annoying
      # pMessage is a pointer to a SecBufferDesc structure
      # which describes an array of SecBuffer structures
      p = event.get_process()
      l = p.get_label_at_address(ra)

      # really ought to use a ctypes struct for this!
      ulVersion = p.peek_uint(pMessage)
      cBuffers = p.peek_uint(pMessage + 4)
      pBuffers = p.peek_uint(pMessage + 8)

      log("[*] <%d:%d> %s 0x%x: EncryptMessage(...)" % (pid,tid,l,ra))
      log("[D]   ulVersion: %d" % ulVersion)
      log("[D]   cBuffers:  %d" % cBuffers)
      log("[D]   pBuffers:  0x%x" % pBuffers)

      # dump buffer list
      for i in range(0,cBuffers):
        cbBuffer = p.peek_uint(pBuffers + (i * 12) + 0)
        BufferType = p.peek_uint(pBuffers + (i * 12) + 4)
        pvBuffer = p.peek_uint(pBuffers + (i * 12) + 8)

        if (BufferType == 1):	# SECBUFFER_DATA
          # we have data to save
          filename = sys.argv[1] + ".encmsg0x%08x-%d" % (pvBuffer,pid)

          f = open(filename,"ab")
          f.write(p.peek(pvBuffer,cbBuffer))
          f.close()

        log("[D]")
        log("[D]   cbBuffer: 0x%x (%d)" % (cbBuffer,cbBuffer))
        log("[D]   BufferType: 0x%x" % BufferType)
        log("[D]   pvBuffer: 0x%x" % pvBuffer)
    except:
      traceback.print_exc()
      raise


  def post_DecryptMessage(self,event,retval):
    # C.?.1 Get the return address and arguments

    try:
      (ra,(phContext,pMessage,MessageSeqNo,pfQOP)) = self.get_funcargs(event)

      pid = event.get_pid()
      tid = event.get_tid()

      # Right -- this is going to get annoying
      # pMessage is a pointer to a SecBufferDesc structure
      # which describes an array of SecBuffer structures
      p = event.get_process()

      # really ought to use a ctypes struct for this!
      ulVersion = p.peek_uint(pMessage)
      cBuffers = p.peek_uint(pMessage + 4)
      pBuffers = p.peek_uint(pMessage + 8)

      log("[*] <%d:%d> 0x%x: DecryptMessage(...)" % (pid,tid,ra))
      log("[D]   ulVersion: %d" % ulVersion)
      log("[D]   cBuffers:  %d" % cBuffers)
      log("[D]   pBuffers:  0x%x" % pBuffers)

      # dump buffer list
      for i in range(0,cBuffers):
        cbBuffer = p.peek_uint(pBuffers + (i * 12) + 0)
        BufferType = p.peek_uint(pBuffers + (i * 12) + 4)
        pvBuffer = p.peek_uint(pBuffers + (i * 12) + 8)

        if (BufferType == 1):	# SECBUFFER_DATA
          # we have data to save
          filename = sys.argv[1] + ".decmsg0x%08x-%d" % (pvBuffer,pid)
          f = open(filename,"ab")
          f.write(p.peek(pvBuffer,cbBuffer))
          f.close()

        log("[D]")
        log("[D]   cbBuffer: 0x%x (%d)" % (cbBuffer,cbBuffer))
        log("[D]   BufferType: 0x%x" % BufferType)
        log("[D]   pvBuffer: 0x%x" % pvBuffer)
    except:
      traceback.print_exc()
      raise


###
# D. winappdbg debug event handlers
###

  ### D.1
  # create_process
  #
  #     winappdbg defined callback function to handle process creation events
  ###

  def create_process(self,event):
    p = event.get_process()

    pid = event.get_pid()
    tid = event.get_tid()
    
    log("[*] <%d:%d> Create process event for pid %d (%s)" % (pid,tid,p.get_pid(),p.get_image_name()))
    log("[-]   command line: %s" % p.get_command_line())
    #log("[D]   Create process event for pid %d (%d)" % (pid,tid))

    self.eventlog.append({
      "time": time.time(),
      "name": event.get_event_name(),
      "type": "WinAppDbg Event",
      "pid": pid,
      "tid": tid,
      "info": {
        "pid": p.get_pid(),
        "module_base": event.get_module_base(),
        "filename": event.get_filename(),
        "cmdline": p.get_command_line()
      },
    })


  ### D.2
  # exit_process
  #
  #     winappdbg defined callback function to handle process exit events
  ###

  def exit_process(self,event):
    pid = event.get_pid()
    tid = event.get_tid()

    log("[*] <%d:%d> Exit process event for %s: 0x%x" % (pid,tid,event.get_filename(),event.get_exit_code()))

    self.eventlog.append({
      "time": time.time(),
      "name": event.get_event_name(),
      "type": "WinAppDbg Event",
      "pid": pid,
      "tid": tid,
      "info": {
        "module_base": event.get_module_base(),
        "filename": event.get_filename(),
        "exitcode": event.get_exit_code()
      },
    })


  ### D.3
  # create_thread
  #
  #     winappdbg defined callback function to handle thread creation events
  ###

  def create_thread(self,event):
    pid = event.get_pid()
    tid = event.get_tid()

    t = event.get_thread()
    name = t.get_name()
    
    log("[*] <%d:%d> Create thread event \"%s\" @ 0x%x" % (pid,tid,name,event.get_start_address()))

    self.eventlog.append({
      "time": time.time(),
      "name": event.get_event_name(),
      "type": "WinAppDbg Event",
      "pid": pid,
      "tid": tid,
      "info": {
        "startaddress": event.get_start_address(),
        "threadname": name
      },
    })


  ### D.4
  # exit_thread
  #
  #     winappdbg defined callback function to handle thread exit events
  ###

  def exit_thread(self,event):
    pid = event.get_pid()
    tid = event.get_tid()

    t = event.get_thread()
    name = t.get_name()

    log("[*] <%d:%d> Exit thread event \"%s\"" % (pid,tid,name,))

    self.eventlog.append({
      "time": time.time(),
      "name": event.get_event_name(),
      "type": "WinAppDbg Event",
      "pid": pid,
      "tid": tid,
      "info": {
        "threadname": name
      },
    })


  ### D.5
  # load_dll
  #
  #     winappdbg defined callback function to handle DLL load events
  ###

  def load_dll(self,event):
    pid = event.get_pid()
    tid = event.get_tid()

    log("[*] <%d:%d> Load DLL event: %s" % (pid,tid,event.get_filename()))

    self.eventlog.append({
      "time": time.time(),
      "name": event.get_event_name(),
      "type": "WinAppDbg Event",
      "pid": pid,
      "tid": tid,
      "info": {
        "module_base": event.get_module_base(),
        "filename": event.get_filename(),
      },
    })


  ### D.6
  # event
  #
  #     winappdbg defined callback function to handle any remaining events
  ###

  def event(self,event):
    pid = event.get_pid()
    tid = event.get_tid()

    log("[*] <%d:%d> Unhandled event: %s" % (pid,tid,event.get_event_name()))


###
# E. winappdbg debug exception handlers
###

  ### E.1
  # guard_page
  #
  #     winappdbg defined callback function to handle guard page exceptions
  ###

  def guard_page_exemem(self,exception):
    try:
      f_type = exception.get_fault_type()

      e_addr = exception.get_exception_address()
      f_addr = exception.get_fault_address()

      # get the process and thread ids
      pid = exception.get_pid()
      tid = exception.get_tid()

      # It is interesting to log this, but it generates a lot of log 
      # output and slows the whole process down
      #log("[!] <%d:%d> 0x%x: GUARD_PAGE(%d) exception for address 0x%x" % (pid,tid,e_addr,f_type,f_addr))
      #log("[*] VirtualAlloc()d memory address 0x%x accessed (%d) from 0x%x (%s)" % (f_addr,f_type,e_addr,instr))

      # E.1.2 Was it a memory write operation?
      if (f_type == winappdbg.win32.EXCEPTION_WRITE_FAULT):
        # E.1.2.1 Use the writeaddrs[] array to check to see 
        #         if we have already logged access from this
        #         address, as unpacking is generally done in 
        #         a loop and we don't want to log the same
        #         instructions for each iteration
        if not e_addr in self.writeaddrs:
          p = exception.get_process()
          t = exception.get_thread()
          label = p.get_label_at_address(e_addr)
          instr = t.disassemble_instruction(e_addr)[2].lower()
          log("[*] VirtualAlloc()d memory address 0x%x written from 0x%x (%s): %s" % (f_addr,e_addr,label,instr))
          self.writeaddrs[e_addr] = instr

        # E.1.2.2 Use the tracing variable to see if we have
        #         already started tracing, that is single 
        #         stepping. If not, enable it, and make a note
        #         of the fact by setting the tracing variable
        #         to True
        if (self.tracing == -1):
          self.tracing = 0
          d = exception.debug
          log("[-]   Enabling tracing")
          d.start_tracing(exception.get_tid())

      # E.1.3 Was it a memory instruction fetch (execute) operation, 
      #       and if so, are we still looking for the entry point address?
      if (f_type == winappdbg.win32.EXCEPTION_EXECUTE_FAULT) and (self.entrypt == 0):
        self.entrypt = e_addr
        t = exception.get_thread()
        jmpinstr = t.disassemble_instruction(self.lasteip[0])[2].lower()

        # E.1.3.1 Log what we've found
        #log("[D]     lasteip[1]: 0x%x" % self.lasteip[1])
        log("[*]   Found unpacked entry point at 0x%x called from 0x%x (%s) (after executing %d instructions)" % (self.entrypt,self.lasteip[0],jmpinstr,self.tracing))
        log("[-]   Unpacking loop at 0x%x - 0x%x" % (self.lowesteip,self.highesteip))

        pid = exception.get_pid()
        tid = exception.get_tid()

        elog = ({
          "time": time.time(),
          "name": "unpacking loop found",
          "type": "unpack event",
          "pid": pid,
          "tid": tid,
          "info": {
            "unpacked_entry_point": self.entrypt,
            "callingaddr": self.lasteip[0],
            "callinginstr": jmpinstr
          },
        })

        # E.1.3.2
        for (mem_pid,memblk) in self.allocedmem:
          if (mem_pid == pid):
            size = self.allocedmem[(mem_pid,memblk)]
            endaddr = memblk + size - 1
            if (e_addr >= memblk) and (e_addr <= endaddr):
              # E.1.3.3 Log what we're doing and delete the memory breakpoint
              log("[-]   Dumping %d bytes of memory range 0x%x - 0x%x" % (size,memblk,endaddr))
              d = exception.debug
              d.dont_watch_buffer(exception.get_pid(),memblk,size - 1)

              # E.1.3.4 Disable single-step debugging
              self.tracing = -1
              d.stop_tracing(exception.get_tid())

              # E.1.3.5 Reset unpacking loop variables
              self.entrypt = 0x00000000
              #del self.lasteip
              self.lasteip = [0x00000000,0x00000000]
              self.lowesteip = 0xffffffff
              self.highest = 0x00000000

              # E.1.3.6 Dump the memory block to a file
              p = exception.get_process()

              filename = sys.argv[1] + ".memblk0x%08x" % memblk
              dumpfile = open(filename,"wb")
              dumpfile.write(p.read(memblk,size))
              dumpfile.close()

              elog["info"]["filename"] = filename
        self.eventlog.append(elog)
    except Exception as e:
      traceback.print_exc()
      raise


  ### E.2
  # single_step
  #
  #     winappdbg defined callback function to handle single step exceptions
  ###

  def single_step(self,exception):
    try:
      # E.2.1 Get the exception address
      e_addr = exception.get_exception_address()

      # E.2.2 If we have just looped back (eip has gone backward)
      if (e_addr < self.lasteip[1]):
        # Remember this lower address as the lowest loop address
        if self.lowesteip == 0xffffffff: self.lowesteip = e_addr

        # ... and the address we just jumped from as the highest loop address
        if self.highesteip == 0x00000000: self.highesteip = self.lasteip[1]

      # E.2.3 If we are executing an instruction within the bounds of the loop
      #       and we haven't already disassembled this address, then do so
      if (e_addr >= self.lowesteip) and (e_addr <= self.highesteip) and (not e_addr in self.disasmd):
        t = exception.get_thread()
        disasm = t.disassemble_instruction(e_addr)
        instr = disasm[2].lower()
        log("    0x%x: %s" % (e_addr,instr))
        self.disasmd.append(e_addr)

      # E.2.4 Remember the last two instruction addresses (eip values)
      #       We need to remember the last two in order to be able to
      #       disassemble the instruction that jumped to the original 
      #       entry point in the unpacked code
      self.lasteip[0] = self.lasteip[1]
      self.lasteip[1] = e_addr

      # E.2.5 Increment the instruction counter, and check to see if 
      #       we have reached our limit of 250,000 instructions.
      #       If so, assume that there is no unpacking loop and stop
      #       tracing (to speed up execution).
      self.tracing += 1
      if (self.tracing >= 250000):
        log("[E] Reached tracing limit of 250000 instructions")

        d = exception.debug
        pid = exception.get_pid()
        d.break_at(pid,e_addr,self.bp_stoptracing)

        self.tracing = -1
    except Exception as e:
      traceback.print_exc()
      raise


  # E.2.6 bp_stoptracing()
  #       Set as a breakpoint handler when we want to stop tracing, as we can't
  #       disable single-step tracing from within the single-step call-back function.

  def bp_stoptracing(self,exception):
    log("[D] Single-step instruction limit reached -- stopping tracing")
    d = exception.debug
    tid = exception.get_tid()
    pid = exception.get_pid()
    d.stop_tracing(tid)
    d.dont_break_at(pid,exception.get_exception_address())


  ### E.3
  # exception
  #
  #     winappdbg defined callback function to handle remaining exceptions
  ###

  def exception(self,exception):
    log("[*] Unhandled exception at 0x%x: %s" % (exception.get_exception_address(),exception.get_exception_name()))
    #log("[-]   0x%x fault at 0x%x" % (exception.get_fault_type(),exception.get_fault_address()))


#
#### end of MyEventHandler class
#


###
# F. Miscellaneous functions
###

### F.1
# log(msg):
###
def log(msg):
  global logfile

  print(msg)
  if not logfile:
    logfile = open(sys.argv[1] + ".log","w")
  if logfile:
    logfile.write(msg + "\n")
    logfile.flush()

  #logfile.log_text(msg)


### F.2
# simple_debugger(argv):
###
def simple_debugger(filename):
  global logfile

  try:
    handler = MyEventHandler()
    #logfile = winappdbg.textio.Logger(filename + ".log",verbose = True)
  except:
    traceback.print_exc()
  with winappdbg.Debug(handler,bKillOnExit = True,bHostileCode = False) as debug:
    log("[*] Starting %s" % filename)
    debug.execl(filename,bFollow = False)
    log("[*] Starting debug loop")
    debug.loop()
    log("[*] Terminating")

  log("[D] Number of created processes: %d" % len(handler.createdprocesses))
  for i in range(0,len(handler.eventlog)):
    log("%s" % handler.eventlog[i])


###
# G. Start of script execution
###

log("[*] Started at %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
simple_debugger(sys.argv[1])
log("[*] Completed at %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
