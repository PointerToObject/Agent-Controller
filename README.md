# Process Hook & Controller Example

This project is a small proof-of-concept that demonstrates:
- DLL injection into a target process
- Setting breakpoints via a vectored exception handler (VEH)
- Reading values from the stack without stepping through instructions
- Communicating between the injected DLL and an external controller using a named pipe
- 
<img width="1230" height="616" alt="hookveh" src="https://github.com/user-attachments/assets/03bbc2a2-608b-4d57-868f-993077eaa997" />

## Overview

The setup has three parts:

1. **Target (`process.exe`)**  
   A simple program that allocates memory, stores a value, and prints it repeatedly.  
   This is just for testing — in a real scenario, it would be any program you want to hook.

2. **Agent DLL (`agent.dll`)**  
   Gets injected into the target process.  
   - Connects to the controller via a named pipe  
   - Scans for a specific byte pattern inside the process memory  
   - Sets a software breakpoint (`INT3`) at the found location  
   - When hit, the VEH reads a value from the stack and sends it to the controller  
   - Has some debug hotkeys (F2, F3, F4, F5) for testing features like reading bytes, listing thread IDs, etc.

3. **Controller (`controller.cpp`)**  
   - Finds the target process by name  
   - Creates the named pipe  
   - Injects the DLL into the process  
   - Prints any messages received from the agent DLL

## How It Works

- The **controller** waits for the target process to open, then injects the agent DLL using `CreateRemoteThread` + `LoadLibraryA`.
- The **agent DLL** connects back to the pipe and starts listening for hotkey presses.
- On `F5`, it pattern-scans for a hardcoded byte sequence in the target's `.text` section and sets a breakpoint there.
- When the breakpoint hits, the **VEH** handler reads a value from `RSP + 0x30` (where the target program stores its variable pointer), sends it through the pipe, restores the original byte, and resumes execution.

## Hotkeys

- **F2** → Print the module base address  
- **F3** → Print the first 5 bytes at the test address  
- **F4** → List all thread IDs in the process  
- **F5** → Scan for the pattern and set the VEH breakpoint

## Notes

- This is purely for educational purposes.  
- The byte pattern and offset values are specific to the test program here — they will need to be changed for other binaries.  
- Right now, it uses `PAGE_EXECUTE_READWRITE` for patching which is not stealthy. Anti-cheat systems will detect this easily.  
- No cleanup is implemented when unloading the DLL.

---

