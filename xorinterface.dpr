library xorinterface;

uses
  System.SysUtils,
  System.Classes,
  Winapi.Windows,
  xorMembridge in '..\..\common\xorMembridge.pas';

{$R *.res}


type
  TOpcodeLenPair = record
    op: integer;
    len: integer;
  end;

const

  (*
    00779F70    .  8B5424 04              MOV     EDX, DWORD PTR SS:[ESP+4]                     ;  mswsock.703E17CD
    00779F74    .  56                     PUSH    ESI
    00779F75    .  8BF1                   MOV     ESI, ECX
    00779F77    .  52                     PUSH    EDX
    00779F78    .  8B46 08                MOV     EAX, DWORD PTR DS:[ESI+8]
    00779F7B    .  8D4E 08                LEA     ECX, DWORD PTR DS:[ESI+8]
    00779F7E    .  FF50 0C                CALL    DWORD PTR DS:[EAX+C]
    00779F81    .  50                     PUSH    EAX                                           ; /Arg1 = 00000000
    00779F82    .  8D8E 14010000          LEA     ECX, DWORD PTR DS:[ESI+114]                   ; |
    00779F88    .  E8 13000000            CALL    ELEMENTC.00779FA0                             ; \ELEMENTC.00779FA0
    00779F8D    .  5E                     POP     ESI                                           ;  ntdll_18.7764F8D1
    00779F8E    .  C2 0400                RETN    4

  *)
    XOR_DecompressARCFourSecurity_PATTERN_LEN = 33;
  XOR_DecompressARCFourSecurity_PATTERN:
    array [0 .. XOR_DecompressARCFourSecurity_PATTERN_LEN - 1] of byte = ($8B, $54, $24, $04, $56,
    $8B, $F1, $52, $8B, $46, $08, $8D, $4E, $08, $FF, $50, $0C, $50, $8D, $8E, $14, $01, $00, $00, $E8, $13, $00, $00,
    $00, $5E, $C2, $04,
    $00);

  // lowest address where we will start searching for the code
  // if it can't be found, we search complete address space, from 0x00400000
  XOR_DecompressARCFourSecurity_SEARCH_STARTADDRESS = $00600000;
  XOR_DecompressARCFourSecurity_SEARCH_ENDADDRESS = $00A00000;

var
  // Address of GNET::DecompressARCFourSecurity::_DecompressARCFourSecurity
    HookPoint_Address: Cardinal;
  Dll_reason: Cardinal;
  params: TxorDLLInitParams;
  local_data: TxorMemBridgeSharedMemory;
  local_client_info: TxorMemBridgeSharedMemoryClientInfo;
  local_bot_commands: TxorTxorMemBridgeSharedMemoryBotCommands;
  // shared memory name
  xmb_bridge: TxorMemBridge;
  xmb_bridge_info: TxorMemBridge;
  xmb_bridge_commands: TxorMemBridge;

function SearchHookPoint(): boolean;
var
    pivot_ram, pivot_array: Cardinal;
  cmp_array: array [0 .. XOR_DecompressARCFourSecurity_PATTERN_LEN - 1] of byte;
  scan_finished: boolean;
begin
  result := false;

  // search starts at base by default to speed it up
  pivot_ram := XOR_DecompressARCFourSecurity_SEARCH_STARTADDRESS;
  pivot_array := 0;
  scan_finished := false;

  while (scan_finished = false) do
  begin
    // load a byte into the cmp_array
    // cmp_array[pivot_array] := PByte(pointer(pivot_ram))^;
    CopyMemory(@cmp_array[pivot_array], pointer(pivot_ram), 1);
    if (cmp_array[pivot_array] = XOR_DecompressARCFourSecurity_PATTERN[pivot_array]) then
    begin
      // matches so far, increment both!
      inc(pivot_array);
      inc(pivot_ram);

      if (pivot_array >= XOR_DecompressARCFourSecurity_PATTERN_LEN) then
      begin
        // we found it!
        result := true;
        // return start address of proc
        HookPoint_Address := pivot_ram - XOR_DecompressARCFourSecurity_PATTERN_LEN;
        scan_finished := true;
      end

    end
    else
    begin
      // it stopped matching somewhere in array.
      // increment the ram pivot by current array pivot.
      inc(pivot_ram, pivot_array + 1);
      // reset array pivot to 0.
      pivot_array := 0;
    end;

    // we do not want to loop indefinitely
    if (pivot_ram > XOR_DecompressARCFourSecurity_SEARCH_ENDADDRESS)
    then
    begin
      result := false;
      scan_finished := true;
    end;

  end;

end;

procedure DumpDebugLog();
var
    sl: TStringList;
  i_p: integer;
  i_p_d: integer;
  packet_str: AnsiString;
begin

  { // add packets
    for i_p := 0 to length(packet_array) - 1 do
    begin
    packet_str := '';
    for i_p_d := 0 to 1023 do
    packet_str := packet_str + ' ' + IntToHex(packet_array[i_p].data[i_p_d], 2);
    sl.Add('Packet : ' + packet_str);
    end;

    sl.SaveToFile('xor_debug_dump.txt');
    sl.Free; }
end;

function ReadCUInt(ptr: pointer; start: integer; out value: integer): integer;
var
    bytes: array [0 .. 7] of byte;
begin
  CopyMemory(@bytes[0], ptr, 8);

  if bytes[0 + start] < $80 then
  begin
    value := bytes[0];
    result := 1;
  end
  else
    if bytes[0 + start] < $C0 then
  begin
    value := ((bytes[0 + start] shl 8) or bytes[1 + start]) and $3FFF;
    result := 2;
  end
  else
  begin
    value := ((bytes[0 + start] shl 24) or (bytes[1 + start] shl 16) or (bytes[2 + start] shl 8) or bytes[3 + start])
      and $1FFFFFFF;
    result := 4;
  end;

end;

// gets called, gets pointer and packet from eax.
procedure Callback_OnIncomingPacket(); stdcall;
var
    octet_offset: pointer;
  r_len: integer;
  val: integer;
begin
  asm
    pushad
    // mov eax, [eax]
    mov eax, [eax+4] // octet.base
    mov octet_offset, eax
    popad
  end;

  inc(local_data.coherency_count);

  r_len := ReadCUInt(octet_offset, 0, val);
  local_data.packet_history[local_data.packet_index].opcode := val;
  r_len := ReadCUInt(octet_offset, r_len, val);
  local_data.packet_history[local_data.packet_index].len := val;

  CopyMemory(@local_data.packet_history[local_data.packet_index].data[0], octet_offset, XOR_PACKET_LEN_MAX);

  inc(local_data.packet_index);
  if (local_data.packet_index >= XOR_SHM_PACKET_HISTORY_COUNT) then
    local_data.packet_index := 0;

  // TODO : maybe only at max every 500 ms?
  xmb_bridge.WriteMem(@local_data, sizeof(TxorMemBridgeSharedMemory));
  // PostMessageA(params.bot_form_handle, params.bot_unique_message, integer(xorMembridgeMessage_packet_recv), 0);

  // do whatever else we need. This is only way our code will get executed, don't forget that.
  // copy name. Bot will write to this shm and update it for us.

  local_client_info.name := local_bot_commands.ident_name;
  xmb_bridge_info.WriteMem(@local_client_info, sizeof(TxorMemBridgeSharedMemoryClientInfo));
end;

procedure ManipulateHookPoint_Recv();
var
    base_addr: Cardinal;
  OldProtect: longword;

begin
  // last 2 instructions get overwritten, we need to jump to callback first, and then back.
  base_addr := HookPoint_Address + XOR_DecompressARCFourSecurity_PATTERN_LEN;
  VirtualProtect(pointer(base_addr), XOR_DecompressARCFourSecurity_PATTERN_LEN + 100, PAGE_EXECUTE_READWRITE,
    OldProtect);

  base_addr := HookPoint_Address + XOR_DecompressARCFourSecurity_PATTERN_LEN - 4;
  PByte(pointer(base_addr))^ := $BA; // mov edx, addr
  inc(base_addr);
  PDWORD(pointer(base_addr))^ := Cardinal(@Callback_OnIncomingPacket);
  inc(base_addr, 4); // addr

  PByte(pointer(base_addr))^ := $FF; // CALL
  inc(base_addr, 1);

  PByte(pointer(base_addr))^ := $D2; // EDX
  inc(base_addr, 1);

  // add last 4 bytes of original instruction
  // POP     ESI
  // RETN    4
  PByte(pointer(base_addr))^ := $5E;
  PByte(pointer(base_addr + 1))^ := $C2;
  PByte(pointer(base_addr + 2))^ := $04;
  PByte(pointer(base_addr + 3))^ := $00;
end;

procedure InitXorHook;
var
    xmb_shm_name: AnsiString;
  local_pid: Cardinal;
begin

  local_pid := GetCurrentProcessId();

  // zero local data
  ZeroMemory(@local_data, sizeof(TxorMemBridgeSharedMemory));
  ZeroMemory(@local_client_info, sizeof(TxorMemBridgeSharedMemoryClientInfo));
  ZeroMemory(@local_bot_commands, sizeof(TxorTxorMemBridgeSharedMemoryBotCommands));

  // create a name for the shared memory, which both the bot and the dll will be able to know beforehand.
  // bot needs to know address if the
  xmb_shm_name := XOR_SHM_NAME_PREFIX + IntToStr(local_pid);
  xmb_bridge := TxorMemBridge.Create(xmb_shm_name, sizeof(TxorMemBridgeSharedMemory));
  // local_data.dll_xor_init_addr := Int64(@InitXorHook);
  xmb_bridge.WriteMem(@local_data, sizeof(TxorMemBridgeSharedMemory));

  // create client info shared memory
  xmb_shm_name := XOR_SHM_NAME_INFO_PREFIX + IntToStr(local_pid);
  xmb_bridge_info := TxorMemBridge.Create(xmb_shm_name, sizeof(TxorMemBridgeSharedMemoryClientInfo));

  local_client_info.pid := local_pid;
  local_client_info.hook_time := GetTickCount;
  GetWindowText(0, @local_client_info.window_title[0], 128);
  GetModuleFileName(0, @local_client_info.exe_path[0], MAX_PATH);

  xmb_bridge_info.WriteMem(@local_client_info, sizeof(TxorMemBridgeSharedMemoryClientInfo));

  // create shm for accepting bot commands
  xmb_shm_name := XOR_SHM_NAME_COMMAND_PREFIX + IntToStr(local_pid);
  xmb_bridge_commands := TxorMemBridge.Create(xmb_shm_name, sizeof(TxorTxorMemBridgeSharedMemoryBotCommands));
  xmb_bridge_commands.WriteMem(@local_bot_commands, sizeof(TxorTxorMemBridgeSharedMemoryBotCommands));

  if (SearchHookPoint()) then
  begin
    ManipulateHookPoint_Recv();
    // PostMessageA(params.bot_form_handle, params.bot_unique_message, integer(xorMembridgeMessage_Init_success), 0);
  end
  else
  begin
    // PostMessageA(params.bot_form_handle, params.bot_unique_message, integer(xorMembridgeMessage_Init_fail), 0);
  end;

end;

procedure Init(Reason: integer);
begin
  Dll_reason := Reason;
  HookPoint_Address := 0;
  // MessageBox(0, 'Injected!', 'Injected!', 0);
  if (Reason = DLL_PROCESS_ATTACH) then
  begin
    // MessageBox(0, 'DLL_PROCESS_ATTACH!', 'DLL_PROCESS_ATTACH!', 0);
    // SetWindowText(GetActiveWindow(),'[xorPW] Hooked! ;)');
    InitXorHook;

  end;
end;

exports InitXorHook index 1;

begin
  DLLProc := Init;
  Init(DLL_PROCESS_ATTACH);

end.
