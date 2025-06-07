typedef struct {
    HANDLE pid;
    PVOID addr;
    PVOID buff;
    ULONG SZ;
    ULONG type;
    HANDLE threadId;
} Kernel_Req, * PKernel_Req;


void jmp(PVOID target, PVOID destination) {
    UCHAR jmpInstruction[HOOK_SIZE] = {
        0x48, 0xB8,                      // mov rax, imm64
        0, 0, 0, 0, 0, 0, 0, 0,          // placeholder
        0xFF, 0xE0                       // jmp rax
    };

    *(PVOID*)&jmpInstruction[2] = destination;  

    RtlCopyMemory(target, jmpInstruction, HOOK_SIZE);
}

//Pega endereços base ex win32kfull.sys
PVOID getMod(PUNICODE_STRING name) {
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsLoadedModuleList");
    PLIST_ENTRY PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&routineName);

    if (!PsLoadedModuleList) return NULL;

    for (PLIST_ENTRY entry = PsLoadedModuleList->Flink; entry != PsLoadedModuleList; entry = entry->Flink) {
        PKLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (mod->FullDllName.Buffer && wcsstr(mod->FullDllName.Buffer, name->Buffer)) {
            return mod->DllBase;
        }
    }

    return NULL;
}
//--------------------------------------------------------
//Hook 

#pragma code_seg(push, "PAGE")
__declspec(code_seg("PAGE"))
extern HANDLE __stdcall Hk() {
    //__debugbreak();
    static ULONG count = 0;
    PEPROCESS callerProc = PsGetCurrentProcess(); // pega o PEPROCESS que fez a syscall


    if (KeGetCurrentIrql() > PASSIVE_LEVEL) // previni bsods
        goto call_original;

    PETHREAD thread = PsGetCurrentThread(); // pega a thread que fez a syscall....
    PVOID teb = PsGetThreadTeb(thread); // pega a TEB da thread , pra acessar tlsSlots

    if (!teb || (ExGetPreviousMode() != UserMode)) { // se não for syscall do usermode... ou teb for nullptr
        goto call_original;
    }

    PVOID* tlsSlots = (PVOID*)((PUCHAR)teb + 33333232323); // pega a tls com offset hardcoded 
    if (!tlsSlots) { // se for nullptr
        goto call_original;
    }

    Kernel_Req* req = NULL; // nosso tipo maligno
    PEPROCESS targetProc = NULL; // processo alvo

    __try {
        if (!MmIsAddressValid(tlsSlots) || !MmIsAddressValid(&tlsSlots[63])) //checka se são validos...
            goto call_original;

        req = (Kernel_Req*)tlsSlots[63]; // typecast com nosso tipo maligno

        if (!MmIsAddressValid(req))
            goto call_original;

        if (!req)
            goto call_original;

        if (MmIsAddressValid(req) == FALSE)
            goto call_original;

        if (req->type != REQ_READ && req->type != REQ_WRITE &&
            req->type != REQ_ALLOC && req->type != REQ_EXEC) // se a comunicação nao for valida
            goto call_original; 

        DbgPrint("[hook][My Driver] teb: %p", teb); // addr da teb
        DbgPrint("[hook][My Driver] tls[63]: %p", tlsSlots[63]); // addr da tls[63]
        DbgPrint("[hook][My Driver] req type: 0x%X", req ? req->type : 0xFFFFFFFF); // printa o tipo da requisicao
        DbgPrint("[hook][My Driver] PID: %lu\n", req->pid); // process id
        DbgPrint("[hook][My Driver] buff: %p\n", req->buff); // addr do buff usermode

        if (!NT_SUCCESS(PsLookupProcessByProcessId(req->pid, &targetProc))) { //pega o processo vitima
            DbgPrint("[-][My Driver] PsLookupProcessByProcessId err\n");
            goto call_original;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-][My Driver] err tls req excpetion \n");
        goto call_original;
    }

call_original:
    // Restaurar bytes originais
    __writecr0(__readcr0() & ~0x10000); // desativa a proteção de escrita
    _disable();
    RtlCopyMemory((PVOID)oGFn, originalBytes, HOOK_SIZE);
    _enable();
    __writecr0(__readcr0() | 0x10000); // ativa a proteção de escrita

    // CALL
    HANDLE result = ((TFN)oGFn)(); //chama a funcao original........

    // Reinstalar hook
    __writecr0(__readcr0() & ~0x10000);
    _disable();
    jmp((PVOID)oGFn, (PVOID)Hk);
    _enable();
    __writecr0(__readcr0() | 0x10000);

    return result;
}
#pragma code_seg(pop)

//mainThread
VOID mainThread(PVOID context) {
    UNREFERENCED_PARAMETER(context);
    DbgPrint("[+][My Driver] i am alive\n");

    HANDLE pid;
    if (!NT_SUCCESS(name2pid(L"explorer.exe", &pid))) { //pega o pid do explorer
        DbgPrint("[-][My Driver] can't get explorer PID\n");
        return;
    }

    PEPROCESS proc;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc))) { // pega o PEPROCESS do explorer
        DbgPrint("[-][My Driver] can't get PEPROCESS\n"); 
        return;
    }

    KAPC_STATE apc; 
    KeStackAttachProcess(proc, &apc); //anexa nosso thread na memoria do explorer, porque win32kfull.sys e todo driver gdi é session space, ou seja não são carregados globalmente

    __try {
        RtlInitUnicodeString(&modName, L"win32kfull.sys");
        PVOID base = getMod(&modName); //pega o endereço de win32kfull.sys na memoria do explorer.exe
        if (!base) {
            DbgPrint("[-][My Driver] can't find base\n");
            __leave;
        }

        ULONG_PTR target = (ULONG_PTR)base + 3232323232; // peguei no windbg
        oGFn = (TFN)target; // cast

        DbgPrint("[+][My Driver] Hooking address: %p\n", target);

        // Salvar os bytes originais
        RtlCopyMemory(originalBytes, (PVOID)target, HOOK_SIZE);

        // Desproteger memória
        __writecr0(__readcr0() & ~0x10000);
        _disable();

        // Hook
        jmp((PVOID)target, (PVOID)Hk);

        // proteger memória
        _enable();
        __writecr0(__readcr0() | 0x10000);

        DbgPrint("[+][My Driver] Hook fn addy: %p\n", (PVOID)Hk);

    }
    __finally {
        KeUnstackDetachProcess(&apc); // tira nossa thread do explorer.exe
        ObDereferenceObject(proc);
    }
}














