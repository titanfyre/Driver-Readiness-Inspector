#include "Inspector.h"
#include <Windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <winevt.h>
#include <objbase.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace Inspector { namespace {
constexpr DWORD PropertyLimit=64*1024, DeviceLimit=512, DriverLimit=128;
struct Key { HKEY h=nullptr; ~Key(){if(h)RegCloseKey(h);} };
struct Service { SC_HANDLE h=nullptr; ~Service(){if(h)CloseServiceHandle(h);} };
struct Events { EVT_HANDLE h=nullptr; ~Events(){if(h)EvtClose(h);} };
struct Devices { HDEVINFO h=INVALID_HANDLE_VALUE; ~Devices(){if(h!=INVALID_HANDLE_VALUE)SetupDiDestroyDeviceInfoList(h);} };
struct File {
    HANDLE h=INVALID_HANDLE_VALUE;
    File()=default;explicit File(HANDLE value):h(value){}
    File(const File&)=delete;File& operator=(const File&)=delete;
    File(File&& other) noexcept:h(other.h){other.h=INVALID_HANDLE_VALUE;}
    File& operator=(File&& other) noexcept {if(this!=&other){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);h=other.h;other.h=INVALID_HANDLE_VALUE;}return *this;}
    ~File(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
};
struct LocalBinary {
    std::vector<File> parents;File file;std::wstring path;DWORD error=ERROR_SUCCESS;std::string detail;
    explicit operator bool() const noexcept{return file.h!=INVALID_HANDLE_VALUE&&error==ERROR_SUCCESS;}
};
std::string Utf8(const std::wstring& w) {
    if(w.empty())return {};const int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w.data(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);
    if(!n)return "[invalid Windows UTF-16 label]";std::string s(static_cast<std::size_t>(n),0);
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w.data(),static_cast<int>(w.size()),s.data(),n,nullptr,nullptr);return s;
}
std::wstring Wide(const std::string& s) {
    if(s.empty())return {};const int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(!n)return {};std::wstring w(static_cast<std::size_t>(n),0);MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),w.data(),n);return w;
}
std::string Hex(std::uint32_t n) {std::ostringstream out;out<<"0x"<<std::uppercase<<std::hex<<std::setw(8)<<std::setfill('0')<<n;return out.str();}
Json Failure(DWORD error,std::string detail={}) {return Value(error==ERROR_ACCESS_DENIED?"access_denied":error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND?"not_present":"unavailable",nullptr,error,std::move(detail));}
std::string Time(const SYSTEMTIME& t) {char b[64]{};sprintf_s(b,"%04u-%02u-%02uT%02u:%02u:%02uZ",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);return b;}
std::string Now() {SYSTEMTIME t{};GetSystemTime(&t);return Time(t);}
Json Decode(DWORD type,const std::vector<BYTE>& bytes) {
    if(type==REG_DWORD){if(bytes.size()!=4)return Value("malformed",nullptr,ERROR_INVALID_DATA,"Expected one DWORD.");DWORD v=0;memcpy(&v,bytes.data(),4);return Value("known",v);}
    if(type!=REG_SZ&&type!=REG_EXPAND_SZ&&type!=REG_MULTI_SZ)return Value("unsupported_type",nullptr,ERROR_INVALID_DATATYPE,"Expected a Windows string, multi-string or DWORD.");
    if(bytes.size()%2||bytes.empty())return Value("malformed",nullptr,ERROR_INVALID_DATA,"Invalid UTF-16 registry value size.");
    std::vector<wchar_t> words(bytes.size()/2);memcpy(words.data(),bytes.data(),bytes.size());
    if(words.back()!=0)return Value("malformed",nullptr,ERROR_INVALID_DATA,"Registry string is not NUL terminated.");
    if(type!=REG_MULTI_SZ){const auto end=std::find(words.begin(),words.end(),0);if(std::any_of(end,words.end(),[](wchar_t c){return c!=0;}))return Value("malformed",nullptr,ERROR_INVALID_DATA,"Registry string contains data after its terminator.");
        const std::wstring value(words.begin(),end);if(!value.empty()&&!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr))return Value("malformed",nullptr,ERROR_NO_UNICODE_TRANSLATION,"Registry string contains invalid UTF-16.");return Value("known",Utf8(value));}
    if(words.size()<2||words[words.size()-2]!=0)return Value("malformed",nullptr,ERROR_INVALID_DATA,"Registry multi-string lacks its double terminator.");
    Json list=Json::array();std::size_t at=0;
    while(at<words.size()&&words[at]){auto end=std::find(words.begin()+static_cast<std::ptrdiff_t>(at),words.end(),0);const std::wstring value(words.begin()+static_cast<std::ptrdiff_t>(at),end);if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr))return Value("malformed",nullptr,ERROR_NO_UNICODE_TRANSLATION,"Registry multi-string contains invalid UTF-16.");list.push_back(Utf8(value));at=static_cast<std::size_t>(end-words.begin())+1;}
    if(std::any_of(words.begin()+static_cast<std::ptrdiff_t>(at),words.end(),[](wchar_t c){return c!=0;}))return Value("malformed",nullptr,ERROR_INVALID_DATA,"Registry multi-string contains data after its terminator.");
    return Value("known",list);
}
Json Registry(HKEY key,const wchar_t* name) {
    if(!key)return Failure(ERROR_INVALID_HANDLE);DWORD type=0,size=0;LSTATUS e=RegQueryValueExW(key,name,nullptr,&type,nullptr,&size);
    if(e!=ERROR_SUCCESS)return Failure(static_cast<DWORD>(e));if(size>PropertyLimit)return Value("limit_exceeded",nullptr,ERROR_BUFFER_OVERFLOW,"Registry value exceeds 64 KiB.");
    std::vector<BYTE> bytes(size);e=RegQueryValueExW(key,name,nullptr,&type,bytes.data(),&size);
    if(e!=ERROR_SUCCESS)return Failure(static_cast<DWORD>(e));bytes.resize(size);return Decode(type,bytes);
}
Json SystemRegistry(const wchar_t* path,const wchar_t* name) {
    Key key;const auto e=RegOpenKeyExW(HKEY_LOCAL_MACHINE,path,0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key.h);if(e!=ERROR_SUCCESS)return Failure(static_cast<DWORD>(e));return Registry(key.h,name);
}
Json Property(HDEVINFO set,SP_DEVINFO_DATA& device,DWORD property) {
    DWORD type=0,size=0;
    if(!SetupDiGetDeviceRegistryPropertyW(set,&device,property,&type,nullptr,0,&size)) {
        const DWORD e=GetLastError();if(e!=ERROR_INSUFFICIENT_BUFFER)return Failure(e==ERROR_INVALID_DATA?ERROR_FILE_NOT_FOUND:e);
    }
    if(size>PropertyLimit)return Value("limit_exceeded",nullptr,ERROR_BUFFER_OVERFLOW,"Device property exceeds 64 KiB.");
    std::vector<BYTE> bytes(size);if(!SetupDiGetDeviceRegistryPropertyW(set,&device,property,&type,bytes.data(),size,&size))return Failure(GetLastError());bytes.resize(size);return Decode(type,bytes);
}
std::string Text(const Json& v,const char* fallback="") {return v.value("status","")=="known"&&v.at("value").is_string()?v.at("value").get<std::string>():fallback;}
std::string Base(const std::wstring& path) {const auto at=path.find_last_of(L"\\/");return Utf8(at==std::wstring::npos?path:path.substr(at+1));}
Json System() {
    Json system;
    struct Version {ULONG size,major,minor,build,platform;WCHAR csd[128];};
    using Query=LONG(WINAPI*)(Version*);const auto query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlGetVersion"));
    Version version{};version.size=sizeof(version);
    if(query&&query(&version)>=0)system["os"]=Value("known",{{"major",version.major},{"minor",version.minor},{"build",version.build},{"architecture","x64"}});
    else system["os"]=Value("unavailable",nullptr,ERROR_CALL_NOT_IMPLEMENTED);
    auto boot=SystemRegistry(L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",L"UEFISecureBootEnabled");
    if(boot["status"]=="known"&&boot["value"].is_number_unsigned()) {
        const auto n=boot["value"].get<DWORD>();if(n<=1)boot["value"]=n?"enabled":"disabled";else boot=Value("unknown_value",n,ERROR_INVALID_DATA);
    }
    boot["detail"]="Firmware state reported by Windows. Missing data does not mean Secure Boot is disabled.";system["secure_boot"]=boot;
    system["hvci_configured"]=SystemRegistry(L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",L"Enabled");
    system["hvci_configured"]["detail"]="Configuration value only; runtime enforcement is reported separately.";
    struct Ci {ULONG length,options;};using NtQuery=LONG(WINAPI*)(ULONG,PVOID,ULONG,PULONG);
    const auto ntq=reinterpret_cast<NtQuery>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));Ci ci{sizeof(Ci),0};const LONG status=ntq?ntq(103,&ci,sizeof(ci),nullptr):static_cast<LONG>(0xC0000002);
    if(status>=0)system["hvci_running"]=Value("known",{{"enabled",(ci.options&0x400)!=0},{"audit_mode",(ci.options&0x800)!=0},{"code_integrity_flags",Hex(ci.options)}});
    else system["hvci_running"]=Value(status==static_cast<LONG>(0xC0000022)?"access_denied":"unavailable",nullptr,static_cast<std::uint32_t>(status),"NTSTATUS; no driver compatibility conclusion can be drawn.");
    system["driver_compatibility"]=Value("not_tested",nullptr,0,"This read-only inspection does not run HLK, Driver Verifier or functional tests, or change security settings.");
    return system;
}
void AddServices(const Json& property,std::set<std::wstring>& services) {
    if(property.value("status","")!="known"||!property.at("value").is_array())return;
    for(const auto& n:property.at("value"))if(n.is_string()){auto w=Wide(n.get<std::string>());if(!w.empty()&&w.size()<256)services.insert(std::move(w));}
}
Json Package(HDEVINFO set,SP_DEVINFO_DATA& device) {
    Key key;key.h=SetupDiOpenDevRegKey(set,&device,DICS_FLAG_GLOBAL,0,DIREG_DRV,KEY_QUERY_VALUE);
    if(key.h==INVALID_HANDLE_VALUE){key.h=nullptr;return {{"status",Failure(GetLastError())}};}
    Json package={{"provider",Registry(key.h,L"ProviderName")},{"version",Registry(key.h,L"DriverVersion")},{"date",Registry(key.h,L"DriverDate")},{"inf",Registry(key.h,L"InfPath")}};
    if(package["inf"]["status"]=="known"&&package["inf"]["value"].is_string())package["inf"]["value"]=Base(Wide(package["inf"]["value"].get<std::string>()));
    return package;
}
std::wstring Resolve(std::wstring path) {
    if(path.empty())return {};
    if(path.front()==L'"'){const auto end=path.find(L'"',1);if(end==std::wstring::npos)return {};path=path.substr(1,end-1);}
    if(path.rfind(L"\\??\\",0)==0)path.erase(0,4);
    wchar_t windows[MAX_PATH]{};if(!GetWindowsDirectoryW(windows,MAX_PATH))return {};
    if(_wcsnicmp(path.c_str(),L"\\SystemRoot\\",12)==0)path=std::wstring(windows)+L"\\"+path.substr(12);
    else if(_wcsnicmp(path.c_str(),L"System32\\",9)==0)path=std::wstring(windows)+L"\\"+path;
    if(path.find(L'%')!=std::wstring::npos){const DWORD size=ExpandEnvironmentStringsW(path.c_str(),nullptr,0);if(!size||size>32768)return {};std::wstring expanded(size,0);if(!ExpandEnvironmentStringsW(path.c_str(),expanded.data(),size))return {};expanded.resize(size-1);path=std::move(expanded);}
    std::replace(path.begin(),path.end(),L'/',L'\\');
    if(!LocalBinaryPathSyntax(path))return {};
    const std::wstring drive=path.substr(0,3);if(GetDriveTypeW(drive.c_str())!=DRIVE_FIXED)return {};
    return path;
}
bool SameFinalPath(HANDLE handle,const std::wstring& expected){
    const DWORD size=GetFinalPathNameByHandleW(handle,nullptr,0,FILE_NAME_NORMALIZED|VOLUME_NAME_GUID);if(!size||size>32768)return false;
    std::wstring actual(size,0);const DWORD written=GetFinalPathNameByHandleW(handle,actual.data(),size,FILE_NAME_NORMALIZED|VOLUME_NAME_GUID);
    if(!written||written>=size)return false;actual.resize(written);
    return actual.size()==expected.size()&&CompareStringOrdinal(actual.data(),static_cast<int>(actual.size()),expected.data(),static_cast<int>(expected.size()),TRUE)==CSTR_EQUAL;
}
LocalBinary OpenLocalBinary(const std::wstring& path){
    LocalBinary result;const auto refuse=[&](DWORD error,const char* detail){result.error=error;result.detail=detail;};
    if(!LocalBinaryPathSyntax(path)){refuse(ERROR_INVALID_NAME,"Binary path is outside the plain drive-absolute syntax policy.");return result;}
    const std::wstring drive=path.substr(0,3);wchar_t volume[MAX_PATH]{};
    if(GetDriveTypeW(drive.c_str())!=DRIVE_FIXED||!GetVolumeNameForVolumeMountPointW(drive.c_str(),volume,MAX_PATH)){refuse(ERROR_NOT_SUPPORTED,"The driver binary could not be mapped to a local fixed volume.");return result;}
    const std::wstring root=volume;
    if(root.rfind(L"\\\\?\\Volume{",0)!=0||root.size()>64||root.back()!=L'\\'||GetDriveTypeW(root.c_str())!=DRIVE_FIXED){refuse(ERROR_NOT_SUPPORTED,"A local fixed-volume GUID was not established.");return result;}
    const std::wstring full=root+path.substr(3);if(full.size()>32767){refuse(ERROR_FILENAME_EXCED_RANGE,"Expanded fixed-volume path exceeds the inspection limit.");return result;}
    std::wstring current=root;std::size_t at=root.size();
    for(;;){
        const auto next=at==root.size()&&current==root?root.size():full.find(L'\\',at);
        const bool rootStep=current==root&&at==root.size();
        const bool final=!rootStep&&next==std::wstring::npos;
        if(!rootStep)current=final?full:full.substr(0,next);
        const DWORD access=final?GENERIC_READ:FILE_READ_ATTRIBUTES;
        // Retain parent handles without write/delete sharing while descendants are opened.
        // A busy or uninspectable directory is skipped rather than following a mutable alias.
        const DWORD sharing=final?FILE_SHARE_READ|FILE_SHARE_WRITE:FILE_SHARE_READ;
        File opened(CreateFileW(current.c_str(),access,sharing,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS|(final?FILE_FLAG_SEQUENTIAL_SCAN:0),nullptr));
        if(opened.h==INVALID_HANDLE_VALUE){refuse(GetLastError(),"Local path component could not be opened without reparse traversal; no binary inspection was attempted.");return result;}
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if(GetFileType(opened.h)!=FILE_TYPE_DISK||!GetFileInformationByHandleEx(opened.h,FileAttributeTagInfo,&tag,sizeof(tag))){refuse(ERROR_NOT_SUPPORTED,"The opened path component did not provide regular local-disk metadata.");return result;}
        if(tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT){refuse(ERROR_CANT_ACCESS_FILE,"Reparse points, junctions, symbolic links and cloud placeholders are excluded from binary inspection.");return result;}
        if(((tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0)==final||!SameFinalPath(opened.h,current)){refuse(ERROR_CANT_ACCESS_FILE,"The final local-volume identity or expected file/directory type could not be verified.");return result;}
        if(final){result.path=current;result.file=std::move(opened);return result;}
        result.parents.push_back(std::move(opened));
        if(rootStep){current.clear();at=root.size();}else at=next+1;
    }
}
Json Hash(HANDLE file) {
    LARGE_INTEGER start{};if(!SetFilePointerEx(file,start,nullptr,FILE_BEGIN))return Failure(GetLastError());
    LARGE_INTEGER size{};if(!GetFileSizeEx(file,&size))return Failure(GetLastError());
    if(size.QuadPart<0||size.QuadPart>128ll*1024*1024)return Value("limit_exceeded",nullptr,ERROR_FILE_TOO_LARGE,"Binary hash limit is 128 MiB.");
    BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;LONG status=BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0);
    if(status>=0)status=BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0);
    std::array<BYTE,64*1024> data{};DWORD got=0;DWORD error=0;std::uint64_t total=0;
    while(status>=0){if(!ReadFile(file,data.data(),static_cast<DWORD>(data.size()),&got,nullptr)){error=GetLastError();break;}if(!got)break;total+=got;if(total>128ull*1024*1024){error=ERROR_FILE_TOO_LARGE;break;}status=BCryptHashData(hash,data.data(),got,0);}
    std::array<BYTE,32> digest{};if(!error&&status>=0)status=BCryptFinishHash(hash,digest.data(),static_cast<ULONG>(digest.size()),0);
    if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);
    if(error)return Failure(error);if(status<0)return Value("unavailable",nullptr,static_cast<std::uint32_t>(status),"BCrypt NTSTATUS.");
    std::ostringstream out;out<<std::hex<<std::setfill('0');for(const auto b:digest)out<<std::setw(2)<<static_cast<unsigned>(b);return Value("known",out.str(),0,"File content observed on disk, not a hash of loaded memory.");
}
Json Signature(HANDLE handle,const std::wstring& path) {
    LARGE_INTEGER start{};if(!SetFilePointerEx(handle,start,nullptr,FILE_BEGIN))return Failure(GetLastError());
    WINTRUST_FILE_INFO file{sizeof(file)};file.pcwszFilePath=path.c_str();file.hFile=handle;
    WINTRUST_DATA data{sizeof(data)};data.dwUIChoice=WTD_UI_NONE;data.fdwRevocationChecks=WTD_REVOKE_NONE;data.dwUnionChoice=WTD_CHOICE_FILE;data.pFile=&file;data.dwStateAction=WTD_STATEACTION_VERIFY;
    data.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL|WTD_REVOCATION_CHECK_NONE;
    GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    struct TrustState {GUID* action;WINTRUST_DATA* data;~TrustState(){data->dwStateAction=WTD_STATEACTION_CLOSE;WinVerifyTrust(nullptr,action,data);}} trust{&action,&data};
    const LONG status=WinVerifyTrust(nullptr,&action,&data);
    const std::string label=status==ERROR_SUCCESS?"cached_trust_accepted":status==TRUST_E_NOSIGNATURE||status==TRUST_E_SUBJECT_FORM_UNKNOWN?"no_embedded_signature":status==TRUST_E_BAD_DIGEST?"invalid_digest":"trust_not_established";
    Json result=Value(label,nullptr,static_cast<std::uint32_t>(status),"Offline embedded Authenticode check only; catalog membership and Windows kernel loading policy are not checked. This is not HLK certification or a blocking decision.");
    result["subject"]=nullptr;
    const auto provider=WTHelperProvDataFromStateData(data.hWVTStateData);
    const auto signer=provider?WTHelperGetProvSignerFromChain(provider,0,FALSE,0):nullptr;
    if(signer&&signer->csCertChain&&signer->pasCertChain&&signer->pasCertChain[0].pCert){
        const auto cert=signer->pasCertChain[0].pCert;const DWORD length=CertGetNameStringW(cert,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,nullptr,nullptr,0);
        if(length&&length<PropertyLimit){std::wstring subject(length,0);if(CertGetNameStringW(cert,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,nullptr,subject.data(),length)){subject.resize(length-1);result["subject"]=Utf8(subject);}}
    }
    return result;
}
std::string ServiceState(DWORD n) {switch(n){case SERVICE_STOPPED:return "stopped";case SERVICE_START_PENDING:return "start_pending";case SERVICE_STOP_PENDING:return "stop_pending";case SERVICE_RUNNING:return "running";case SERVICE_PAUSED:return "paused";default:return "state_"+std::to_string(n);}}
Json Driver(SC_HANDLE scm,DWORD scm_error,const std::wstring& name,const Options& options,std::map<std::wstring,Json>& cache) {
    Json result={{"service",Utf8(name)}};if(!scm){result["state"]=Failure(scm_error,"Service manager could not be opened.");return result;}
    Service service;service.h=OpenServiceW(scm,name.c_str(),SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG);
    if(!service.h){result["state"]=Failure(GetLastError());return result;}
    SERVICE_STATUS_PROCESS state{};DWORD length=0;
    if(QueryServiceStatusEx(service.h,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&state),sizeof(state),&length))result["state"]=Value("known",{{"state",ServiceState(state.dwCurrentState)},{"service_type",state.dwServiceType},{"win32_exit_code",state.dwWin32ExitCode}});
    else result["state"]=Failure(GetLastError());
    QueryServiceConfigW(service.h,nullptr,0,&length);const DWORD e=GetLastError();
    if(e!=ERROR_INSUFFICIENT_BUFFER||length>PropertyLimit){result["configuration"]=Failure(e);return result;}
    std::vector<BYTE> config(length);
    if(!QueryServiceConfigW(service.h,reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data()),length,&length)){result["configuration"]=Failure(GetLastError());return result;}
    const auto q=reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(config.data());const std::wstring raw=q->lpBinaryPathName?q->lpBinaryPathName:L"";const auto path=Resolve(raw);
    result["start_type"]=Value("known",q->dwStartType);result["service_type"]=q->dwServiceType;
    result["binary"]=options.include_sensitive?Utf8(raw):Base(path);
    const bool kernel=(q->dwServiceType&(SERVICE_KERNEL_DRIVER|SERVICE_FILE_SYSTEM_DRIVER|SERVICE_RECOGNIZER_DRIVER))!=0;
    if(!kernel){result["binary_inspection"]=Value("not_applicable",nullptr,0,"Device service is not a kernel or filesystem driver; application binaries are not inspected.");return result;}
    if(path.empty()){result["binary_inspection"]=Value("not_inspected",nullptr,0,"Only a resolved local fixed-drive binary path is inspected. Network, unknown or malformed paths are skipped.");return result;}
    auto found=cache.find(path);if(found==cache.end()){
        found=cache.emplace(path,BinaryEvidence(path)).first;
    }
    result.update(found->second);return result;
}
Json RecentEvents(const Options& options) {
    if(!options.events)return {{"status","not_requested"},{"entries",Json::array()}};
    Events query;query.h=EvtQuery(nullptr,L"Microsoft-Windows-CodeIntegrity/Operational",L"*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 604800000]]]",EvtQueryChannelPath|EvtQueryReverseDirection);
    if(!query.h)return {{"status",GetLastError()==ERROR_ACCESS_DENIED?"access_denied":"unavailable"},{"error",GetLastError()},{"entries",Json::array()}};
    Events context;context.h=EvtCreateRenderContext(0,nullptr,EvtRenderContextSystem);
    if(!context.h)return {{"status","unavailable"},{"error",GetLastError()},{"entries",Json::array()}};
    Json result={{"status","known"},{"entries",Json::array()},{"maximum_age_days",7},{"limit",64},{"raw_xml_included",options.include_sensitive},{"more_events",false}};
    for(DWORD i=0;i<65;++i) {
        if(options.stop&&options.stop->load(std::memory_order_relaxed)){result["status"]="cancelled";break;}
        EVT_HANDLE handle=nullptr;DWORD count=0;
        if(!EvtNext(query.h,1,&handle,1000,0,&count)){const DWORD e=GetLastError();if(e!=ERROR_NO_MORE_ITEMS){result["status"]="partial";result["error"]=e;}break;}
        Events event;event.h=handle;if(i==64){result["more_events"]=true;break;}
        DWORD used=0,properties=0;EvtRender(context.h,event.h,EvtRenderEventValues,0,nullptr,&used,&properties);
        if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER||used>PropertyLimit){result["entries"].push_back({{"status","render_failed"},{"error",GetLastError()}});continue;}
        std::vector<BYTE> bytes(used);
        if(!EvtRender(context.h,event.h,EvtRenderEventValues,used,bytes.data(),&used,&properties)||properties<=EvtSystemTimeCreated){result["entries"].push_back({{"status","render_failed"},{"error",GetLastError()}});continue;}
        const auto values=reinterpret_cast<const EVT_VARIANT*>(bytes.data());Json item={{"id",values[EvtSystemEventID].UInt16Val},{"level",values[EvtSystemLevel].ByteVal}};
        if(values[EvtSystemProviderName].Type==EvtVarTypeString&&values[EvtSystemProviderName].StringVal)item["provider"]=Utf8(values[EvtSystemProviderName].StringVal);
        if(values[EvtSystemTimeCreated].Type==EvtVarTypeFileTime){ULARGE_INTEGER time{};time.QuadPart=values[EvtSystemTimeCreated].FileTimeVal;FILETIME ft{time.LowPart,time.HighPart};SYSTEMTIME st{};if(FileTimeToSystemTime(&ft,&st))item["created_utc"]=Time(st);}
        if(options.include_sensitive){used=0;EvtRender(nullptr,event.h,EvtRenderEventXml,0,nullptr,&used,&properties);
            if(GetLastError()==ERROR_INSUFFICIENT_BUFFER&&used<=PropertyLimit){std::vector<wchar_t> xml(used/sizeof(wchar_t)+1,0);if(EvtRender(nullptr,event.h,EvtRenderEventXml,used,xml.data(),&used,&properties))item["raw_xml"]=Utf8(xml.data());else item["raw_xml_error"]=GetLastError();}
            else item["raw_xml_status"]="unavailable_or_larger_than_64_KiB";
        }else item["detail"]="Event payload omitted by default; no path, hash or user-data field is exported.";
        result["entries"].push_back(std::move(item));
    }
    return result;
}
} // namespace
Json BinaryEvidence(const std::wstring& path){
    auto local=OpenLocalBinary(path);
    if(!local)return {{"binary_inspection",Value("not_inspected",nullptr,local.error,local.detail)}};
    auto hash=Hash(local.file.h);auto signature=hash.value("status","")=="known"?Signature(local.file.h,local.path):Value("not_inspected",nullptr,0,"Binary could not be hashed within the local read limits.");
    return {{"sha256",std::move(hash)},{"embedded_signature",std::move(signature)}};
}
Json DecodeRegistryValue(std::uint32_t type,const std::vector<std::uint8_t>& bytes) {return Decode(type,bytes);}
Json Collect(const Options& options) {
    const auto started=std::chrono::steady_clock::now();Json result=Preview();result["created_utc"]=Now();result["scope"]={{"read_only",true},{"preview",false},{"include_sensitive",options.include_sensitive},{"present_devices_only",true},{"network_upload",false}};
    result["system"]=System();result["devices"]=Json::array();result["drivers"]=Json::array();
    result["collection"]={{"device_limit",DeviceLimit},{"driver_service_limit",DriverLimit},{"events_limit",64},{"truncated_devices",false},{"truncated_services",false},{"warnings",Json::array()}};
    Devices guard;guard.h=SetupDiGetClassDevsW(nullptr,nullptr,nullptr,DIGCF_PRESENT|DIGCF_ALLCLASSES);const HDEVINFO set=guard.h;std::set<std::wstring> services;
    if(set==INVALID_HANDLE_VALUE)result["collection"]["device_error"]=GetLastError();
    else {
        for(DWORD index=0;index<=DeviceLimit;++index) {
            if(options.stop&&options.stop->load(std::memory_order_relaxed)){result["collection"]["cancelled"]=true;break;}
            SP_DEVINFO_DATA device{sizeof(device)};
            if(!SetupDiEnumDeviceInfo(set,index,&device)){const DWORD e=GetLastError();if(e!=ERROR_NO_MORE_ITEMS)result["collection"]["enumeration_error"]=e;break;}
            if(index==DeviceLimit){result["collection"]["truncated_devices"]=true;break;}
            auto label=Property(set,device,SPDRP_FRIENDLYNAME);if(Text(label).empty())label=Property(set,device,SPDRP_DEVICEDESC);
            const auto service=Property(set,device,SPDRP_SERVICE),type=Property(set,device,SPDRP_CLASS);
            Json d={{"id","device_"+std::to_string(index+1)},{"name",Text(label,"Unnamed PnP node")},{"name_status",label},{"class",Text(type,"unknown")},{"service",Text(service)},{"service_property",service},{"driver_package",Package(set,device)}};
            if(!Text(service).empty())services.insert(Wide(Text(service)));
            DWORD status=0,problem=0;const auto cr=CM_Get_DevNode_Status(&status,&problem,device.DevInst,0);
            d["pnp"]=cr==CR_SUCCESS?Value("known",{{"problem",problem},{"devnode_status",Hex(status)},{"explanation",Problem(problem)}}):Value(cr==CR_ACCESS_DENIED?"access_denied":"unavailable",nullptr,cr,"Configuration Manager result, not a Windows error code.");
            for(const auto pair:{std::pair<const char*,DWORD>{"device_upper_filters",SPDRP_UPPERFILTERS},{"device_lower_filters",SPDRP_LOWERFILTERS}}){auto property=Property(set,device,pair.second);AddServices(property,services);d[pair.first]=std::move(property);}
            wchar_t guid[64]{};StringFromGUID2(device.ClassGuid,guid,64);const std::wstring keyPath=L"SYSTEM\\CurrentControlSet\\Control\\Class\\"+std::wstring(guid);
            for(const auto pair:{std::pair<const char*,const wchar_t*>{"class_upper_filters",L"UpperFilters"},{"class_lower_filters",L"LowerFilters"}}){auto property=SystemRegistry(keyPath.c_str(),pair.second);AddServices(property,services);d[pair.first]=std::move(property);}
            if(options.include_sensitive){DWORD n=0;SetupDiGetDeviceInstanceIdW(set,&device,nullptr,0,&n);if(n&&n<32768){std::wstring instance(n,0);if(SetupDiGetDeviceInstanceIdW(set,&device,instance.data(),n,&n)){instance.resize(wcslen(instance.c_str()));d["instance_id"]=Utf8(instance);}}}
            result["devices"].push_back(std::move(d));
        }
    }
    Service scm;scm.h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);const DWORD scm_error=scm.h?0:GetLastError();std::map<std::wstring,Json> cache;DWORD count=0;
    for(const auto& name:services){if(options.stop&&options.stop->load(std::memory_order_relaxed)){result["collection"]["cancelled"]=true;break;}if(count++==DriverLimit){result["collection"]["truncated_services"]=true;break;}result["drivers"].push_back(Driver(scm.h,scm_error,name,options,cache));}
    result["code_integrity"]=RecentEvents(options);
    result["collection"]["elapsed_ms"]=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
    result["collection"]["warnings"].push_back("Device friendly names, provider labels and service names are kept for diagnosis and can still identify your hardware. Review reports before sharing.");
    result["collection"]["warnings"].push_back("Filter properties describe registry configuration only. This tool cannot establish a live kernel attachment order or test device behavior.");
    result["collection"]["warnings"].push_back("Inspection occurs over time: devices, services and files may change during a snapshot. No secret, activation key or input content is requested.");
    return result;
}
}
