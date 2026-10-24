#include "../App/Inspector.h"
#include <stdexcept>
#include <Windows.h>
#include <objbase.h>
#include <winioctl.h>
#include <cstring>

namespace {
bool LocalJunction(const std::wstring& link,const std::wstring& target){
    if(!CreateDirectoryW(link.c_str(),nullptr))return false;
    const HANDLE handle=CreateFileW(link.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    if(handle==INVALID_HANDLE_VALUE)return false;
    const auto substitute=L"\\??\\"+target;
    struct Mount {DWORD tag;WORD bytes,reserved,substitute_offset,substitute_bytes,print_offset,print_bytes;};
    static_assert(sizeof(Mount)==16,"Windows mount-point reparse header");
    const auto textBytes=(substitute.size()+1+target.size()+1)*sizeof(wchar_t);std::vector<std::uint8_t> data(sizeof(Mount)+textBytes,0);
    auto* header=reinterpret_cast<Mount*>(data.data());header->tag=IO_REPARSE_TAG_MOUNT_POINT;header->bytes=static_cast<WORD>(8+textBytes);
    header->substitute_bytes=static_cast<WORD>(substitute.size()*sizeof(wchar_t));header->print_offset=static_cast<WORD>((substitute.size()+1)*sizeof(wchar_t));header->print_bytes=static_cast<WORD>(target.size()*sizeof(wchar_t));
    std::memcpy(data.data()+sizeof(Mount),substitute.c_str(),(substitute.size()+1)*sizeof(wchar_t));std::memcpy(data.data()+sizeof(Mount)+header->print_offset,target.c_str(),(target.size()+1)*sizeof(wchar_t));
    DWORD done=0;const bool ok=DeviceIoControl(handle,FSCTL_SET_REPARSE_POINT,data.data(),static_cast<DWORD>(data.size()),nullptr,0,&done,nullptr)!=FALSE;CloseHandle(handle);return ok;
}
}

namespace Inspector {
bool SelfTest(std::string& result) {
    unsigned checks=0;
    const auto check=[&](bool good){++checks;if(!good)throw std::runtime_error("Offline fixture "+std::to_string(checks)+" failed.");};
    try {
        check(HtmlEscape("<script>&\"'")=="&lt;script&gt;&amp;&quot;&#39;");
        check(HtmlEscape(std::string("a\x01z",3))=="a?z");
        auto r=Preview();r["devices"][0]["name"]="<img src=x onerror=alert(1)>";r["devices"][0]["service"]="\"quoted\" & service";
        r["drivers"][0]["service"]="</summary><script>alert(1)</script>";
        auto html=Html(r);check(html.find("<img src=x")==std::string::npos);check(html.find("<script>")==std::string::npos);
        check(html.find("&lt;img src=x")!=std::string::npos);check(html.find("&lt;/summary&gt;")!=std::string::npos);
        check(html.find("default-src 'none'")!=std::string::npos);
        check(Json::parse(JsonText(r))==r);
        check(Problem(0).find("not a functional")!=std::string::npos);check(Problem(52).find("signature")!=std::string::npos);
        check(Problem(1234).find("1234")!=std::string::npos);
        check(Value("access_denied",nullptr,5).at("value").is_null());
        check(DecodeRegistryValue(REG_DWORD,{1,0,0,0}).at("value")==1);
        check(DecodeRegistryValue(REG_DWORD,{1,0,0}).at("status")=="malformed");
        check(DecodeRegistryValue(REG_SZ,{'A',0,0,0}).at("value")=="A");
        check(DecodeRegistryValue(REG_SZ,{'A',0}).at("status")=="malformed");
        check(DecodeRegistryValue(REG_SZ,{'A'}).at("status")=="malformed");
        check(DecodeRegistryValue(REG_MULTI_SZ,{'A',0,0,0,'B',0,0,0,0,0}).at("value")==Json::array({"A","B"}));
        check(DecodeRegistryValue(REG_MULTI_SZ,{'A',0,0,0}).at("status")=="malformed");
        check(DecodeRegistryValue(REG_MULTI_SZ,{0,0,0,0}).at("value")==Json::array());
        check(DecodeRegistryValue(REG_BINARY,{1,2}).at("status")=="unsupported_type");
        check(DecodeRegistryValue(REG_SZ,{'A',0,0,0,'B',0,0,0}).at("status")=="malformed");
        check(DecodeRegistryValue(REG_MULTI_SZ,{'A',0,0,0,0,0,'B',0,0,0,0,0}).at("status")=="malformed");
        check(DecodeRegistryValue(REG_SZ,{0,0xD8,0,0}).at("status")=="malformed");
        check(DecodeRegistryValue(REG_MULTI_SZ,{0,0xD8,0,0,0,0}).at("status")=="malformed");
        check(Summary(Preview()).find("No new driver required")!=std::string::npos);
        check(Summary(Preview()).find("not establish")!=std::string::npos);
        r["devices"][0]["pnp"]=Value("access_denied",nullptr,5);
        check(DeviceSummary(r["devices"][0]).find("access_denied")!=std::string::npos);
        check(ServiceSummary(r["drivers"][0]).find("no_embedded_signature")!=std::string::npos);
        for(const auto& path:{L"C:\\Windows\\System32\\drivers\\example.sys",L"d:\\A folder\\driver-1.sys",L"E:\\driver.sys",L"C:\\COM10.sys",L"C:\\drivers\\module.release.sys",L"C:\\drivers\\\u03A9.sys"})check(LocalBinaryPathSyntax(path));
        for(const auto& path:{L"",L"C:",L"C:\\",L"C:driver.sys",L"\\\\server\\share\\driver.sys",L"\\\\?\\UNC\\server\\share\\driver.sys",L"\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\driver.sys",L"\\Device\\NamedPipe\\name",L"C:\\Windows\\..\\driver.sys",L"C:\\Windows\\.\\driver.sys",L"C:\\Windows\\\\driver.sys",L"C:\\Windows\\driver.sys:stream",L"C:\\drivers.\\driver.sys",L"C:\\drivers \\driver.sys",L"C:\\drivers\\driver.sys.",L"C:\\drivers\\driver.sys ",L"C:\\drivers\\*.sys",L"C:\\drivers\\NUL.sys",L"C:\\CON",L"C:\\AUX.log",L"C:\\drivers\\COM1.sys",L"C:\\drivers\\LPT9",L"C:\\CONIN$",L"C:\\CONOUT$",L"C:\\drivers\\COM\u00B9.sys"})check(!LocalBinaryPathSyntax(path));
        check(!LocalBinaryPathSyntax(std::wstring(L"C:\\drivers\\bad")+wchar_t(0)+L".sys"));
        check(!LocalBinaryPathSyntax(std::wstring(L"C:\\drivers\\")+wchar_t(0xD800)+L".sys"));
        check(!LocalBinaryPathSyntax(std::wstring(L"C:\\drivers\\")+wchar_t(0xDC00)+L".sys"));
        check(!LocalBinaryPathSyntax(L"C:\\"+std::wstring(256,L'a')+L".sys"));
        std::wstring deep=L"C:\\";for(unsigned n=0;n<128;++n)deep+=L"a\\";check(!LocalBinaryPathSyntax(deep+L"driver.sys"));
        unsigned seed=0x12345678u;
        for(unsigned i=0;i<2000;++i){std::vector<std::uint8_t> bytes(i%128);for(auto& b:bytes){seed=seed*1664525u+1013904223u;b=static_cast<std::uint8_t>(seed>>24);}const auto observation=DecodeRegistryValue(i%4==0?REG_DWORD:i%4==1?REG_SZ:i%4==2?REG_MULTI_SZ:REG_BINARY,bytes);check(observation.contains("status")&&observation.contains("value")&&observation.contains("error"));}
        for(unsigned i=0;i<10000;++i){const std::string s="<>&\"'"+std::to_string(i);check(HtmlEscape(s).find('<')==std::string::npos);}
        wchar_t temp[32768]{};const DWORD tempLength=GetTempPathW(32768,temp);check(tempLength>0&&tempLength<32768);
        GUID guid{};check(SUCCEEDED(CoCreateGuid(&guid)));wchar_t name[40]{};check(StringFromGUID2(guid,name,40)>0);
        const std::wstring directory=std::wstring(temp)+L"DRI-Offline-"+name;
        const std::wstring file=directory+L"\\fixture.bin",fileLink=directory+L"\\file-link.bin",directoryLink=directory+L"-directory-link",junction=directory+L"-junction";
        check(LocalBinaryPathSyntax(file));check(CreateDirectoryW(directory.c_str(),nullptr)!=FALSE);
        struct Cleanup{std::wstring file,fileLink,directoryLink,junction,directory;~Cleanup(){DeleteFileW(fileLink.c_str());RemoveDirectoryW(directoryLink.c_str());RemoveDirectoryW(junction.c_str());DeleteFileW(file.c_str());RemoveDirectoryW(directory.c_str());}} cleanup{file,fileLink,directoryLink,junction,directory};
        HANDLE sample=CreateFileW(file.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);check(sample!=INVALID_HANDLE_VALUE);
        DWORD written=0;const bool saved=WriteFile(sample,"abc",3,&written,nullptr)&&written==3;CloseHandle(sample);check(saved);
        const auto evidence=BinaryEvidence(file);check(evidence.contains("sha256"));check(evidence.at("sha256").at("value")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        check(evidence.at("embedded_signature").at("status")=="no_embedded_signature");
        check(LocalJunction(junction,directory));const auto blocked=BinaryEvidence(junction+L"\\fixture.bin");check(blocked.contains("binary_inspection")&&!blocked.contains("sha256"));check(blocked.at("binary_inspection").at("detail").get<std::string>().find("Reparse")!=std::string::npos);
        unsigned linkChecks=0;
        if(CreateSymbolicLinkW(fileLink.c_str(),file.c_str(),SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)){
            const auto refused=BinaryEvidence(fileLink);check(refused.contains("binary_inspection")&&!refused.contains("sha256"));check(refused.at("binary_inspection").at("detail").get<std::string>().find("Reparse")!=std::string::npos);++linkChecks;
        }else check(GetLastError()==ERROR_PRIVILEGE_NOT_HELD||GetLastError()==ERROR_INVALID_PARAMETER||GetLastError()==ERROR_NOT_SUPPORTED);
        if(CreateSymbolicLinkW(directoryLink.c_str(),directory.c_str(),SYMBOLIC_LINK_FLAG_DIRECTORY|SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)){
            const auto refused=BinaryEvidence(directoryLink+L"\\fixture.bin");check(refused.contains("binary_inspection")&&!refused.contains("sha256"));check(refused.at("binary_inspection").at("detail").get<std::string>().find("Reparse")!=std::string::npos);++linkChecks;
        }else check(GetLastError()==ERROR_PRIVILEGE_NOT_HELD||GetLastError()==ERROR_INVALID_PARAMETER||GetLastError()==ERROR_NOT_SUPPORTED);
        result=std::to_string(checks)+" offline escaping/schema/status/path fixtures passed; local directory-junction rejection passed; "+std::to_string(linkChecks)+" optional local symlink cases exercised (others require existing OS permission). Only an owned temporary fixture file was inspected; no driver/device inventory was opened.";return true;
    }catch(const std::exception& e){result=e.what();return false;}
}
}
