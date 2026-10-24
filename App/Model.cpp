#include "Inspector.h"
#include <Windows.h>
#include <algorithm>
#include <sstream>

namespace Inspector {
Json Value(std::string status, Json value, std::uint32_t error, std::string detail) {
    return {{"status", std::move(status)}, {"value", std::move(value)}, {"error", error}, {"detail", std::move(detail)}};
}
bool LocalBinaryPathSyntax(const std::wstring& path) noexcept {
    if(path.size()<4||path.size()>32767||!((path[0]>=L'A'&&path[0]<=L'Z')||(path[0]>=L'a'&&path[0]<=L'z'))||path[1]!=L':'||path[2]!=L'\\')return false;
    std::size_t at=3,parts=0;
    while(at<path.size()){
        if(++parts>128)return false;const auto end=path.find(L'\\',at),last=end==std::wstring::npos?path.size():end;
        if(last==at||last-at>255||path[last-1]==L'.'||path[last-1]==L' ')return false;
        for(std::size_t n=at;n<last;++n){
            const auto c=path[n];if(c<32||c==L'<'||c==L'>'||c==L':'||c==L'"'||c==L'|'||c==L'?'||c==L'*'||c==L'/')return false;
            if(c>=0xD800&&c<=0xDBFF){if(++n>=last||path[n]<0xDC00||path[n]>0xDFFF)return false;}
            else if(c>=0xDC00&&c<=0xDFFF)return false;
        }
        const auto dot=path.find(L'.',at),stemEnd=dot<last?dot:last;const auto stemLength=stemEnd-at;
        const auto upper=[&](std::size_t n){const auto c=path[at+n];return c>=L'a'&&c<=L'z'?static_cast<wchar_t>(c-L'a'+L'A'):c;};
        if(stemLength==3){const wchar_t a=upper(0),b=upper(1),c=upper(2);if((a==L'C'&&b==L'O'&&c==L'N')||(a==L'P'&&b==L'R'&&c==L'N')||(a==L'A'&&b==L'U'&&c==L'X')||(a==L'N'&&b==L'U'&&c==L'L'))return false;}
        if(stemLength==4){const bool port=(upper(0)==L'C'&&upper(1)==L'O'&&upper(2)==L'M')||(upper(0)==L'L'&&upper(1)==L'P'&&upper(2)==L'T');const auto c=upper(3);if(port&&((c>=L'0'&&c<=L'9')||c==0xB9||c==0xB2||c==0xB3))return false;}
        if(stemLength==6&&upper(0)==L'C'&&upper(1)==L'O'&&upper(2)==L'N'&&upper(3)==L'I'&&upper(4)==L'N'&&upper(5)==L'$')return false;
        if(stemLength==7&&upper(0)==L'C'&&upper(1)==L'O'&&upper(2)==L'N'&&upper(3)==L'O'&&upper(4)==L'U'&&upper(5)==L'T'&&upper(6)==L'$')return false;
        if(end==std::wstring::npos)return true;at=end+1;if(at==path.size())return false;
    }
    return false;
}
std::string HtmlEscape(const std::string& text) {
    std::string out; out.reserve(text.size());
    for (const unsigned char c : text) {
        switch (c) {case '&':out+="&amp;";break;case '<':out+="&lt;";break;case '>':out+="&gt;";break;case '"':out+="&quot;";break;case '\'':out+="&#39;";break;
        default:if(c<32&&c!='\n'&&c!='\t'&&c!='\r')out+='?';else out+=static_cast<char>(c);}
    } return out;
}
std::string Problem(std::uint32_t code) {
    switch (code) {
    case 0:return "No PnP problem reported. This is not a functional or compatibility test.";
    case 1:return "Device is not configured correctly. Review its installed package and configuration.";
    case 10:return "Device could not start. Inspect its exact driver and recent events.";
    case 12:return "Device cannot find enough resources.";
    case 14:return "Windows requests a restart for this device.";
    case 18:return "Windows requests driver reinstallation.";
    case 19:return "Windows reports incomplete or damaged registry configuration.";
    case 21:return "Windows is removing the device.";
    case 22:return "Device is disabled.";
    case 24:return "Device is absent, not working correctly, or incompletely installed.";
    case 28:return "Drivers are not installed for this device.";
    case 31:return "Windows cannot load the required drivers. The cause is not established by this code.";
    case 32:return "A required driver service is disabled.";
    case 37:return "Windows could not initialize the device driver.";
    case 39:return "Windows could not load the driver; it may be missing or damaged.";
    case 43:return "The device or driver reported a failure.";
    case 45:return "Device is not connected.";
    case 48:return "Windows reports that this driver is blocked. Inspect Windows events for the exact reason.";
    case 52:return "Windows cannot verify the driver's digital signature. The exact package and policy need investigation.";
    case 54:return "Device failed and is undergoing a reset.";
    default:return "Windows PnP problem code " + std::to_string(code) + "; consult the Microsoft Device Manager error reference.";
    }
}
std::string DeviceSummary(const Json& d) {
    std::ostringstream s;
    s<<d.value("name", "Unnamed device")<<"\r\nClass: "<<d.value("class", "unknown")<<"\r\nService: "<<d.value("service", "")<<"\r\n";
    const auto p=d.at("pnp");
    if(p.value("status", "unknown")=="known")s<<"PnP code: "<<p.at("value").value("problem", 0u)<<"\r\n"<<Problem(p.at("value").value("problem", 0u));
    else s<<"PnP state: "<<p.value("status", "unknown")<<" (error "<<p.value("error",0u)<<")";
    const auto show=[&](const char* label,const Json& value){s<<"\r\n"<<label<<": ";if(value.is_object()&&value.contains("status")){s<<value.value("status","unknown");if(value.contains("value")&&!value.at("value").is_null())s<<" | "<<value.at("value").dump();if(value.value("error",0u))s<<" | error "<<value.value("error",0u);}else s<<value.dump();};
    s<<"\r\n\r\nINSTALLED PACKAGE";
    for(const auto& field:d.at("driver_package").items())show(field.key().c_str(),field.value());
    s<<"\r\n\r\nFILTER CONFIGURATION (REGISTRY METADATA)";
    for(const auto key:{"device_upper_filters","device_lower_filters","class_upper_filters","class_lower_filters"})if(d.contains(key))show(key,d.at(key));
    s<<"\r\nThis is not a verified live attachment order.";
    if(d.contains("instance_id"))s<<"\r\n\r\nSENSITIVE INSTANCE ID: "<<d.at("instance_id").get<std::string>();
    return s.str();
}
std::string ServiceSummary(const Json& d) {
    std::ostringstream s;s<<"SERVICE: "<<d.value("service","")<<"\r\n";
    for(const auto& field:d.items()){
        if(field.key()=="service")continue;s<<field.key()<<": ";const auto& value=field.value();
        if(value.is_object()&&value.contains("status")){s<<value.value("status","unknown");if(value.contains("value")&&!value.at("value").is_null())s<<" | "<<value.at("value").dump();if(value.value("error",0u))s<<" | error "<<value.value("error",0u);if(value.contains("subject")&&!value.at("subject").is_null())s<<" | signer "<<value.at("subject").get<std::string>();if(!value.value("detail","").empty())s<<"\r\n  "<<value.at("detail").get<std::string>();}
        else s<<value.dump();s<<"\r\n";
    }return s.str();
}
std::string Summary(const Json& report) {
    std::ostringstream s;
    s<<"READ-ONLY SNAPSHOT | "<<report.at("devices").size()<<" present device nodes | "<<report.at("drivers").size()<<" associated services\r\n";
    s<<"No new driver required. No installation, activation, input capture or security-setting changes.\r\n";
    s<<"Privacy: "<<(report.at("scope").value("include_sensitive",false)?"raw identifiers, event text and full binary paths included by explicit request.":"instance IDs and full paths excluded; event text redacted.")<<"\r\n";
    s<<"A readable signature or PnP code 0 does not establish HVCI compatibility, HLK certification, or correct device operation.\r\n\r\n";
    for(const auto& pair:report.at("system").items())if(pair.key()!="driver_compatibility"){
        s<<pair.key()<<": "<<pair.value().value("status","unknown");if(!pair.value().at("value").is_null())s<<" | "<<pair.value().at("value").dump();if(pair.value().value("error",0u))s<<" | error "<<pair.value().value("error",0u);s<<"\r\n";
    }
    return s.str();
}
std::string JsonText(const Json& report) {return report.dump(2, ' ', false, Json::error_handler_t::replace)+"\n";}
std::string Html(const Json& report) {
    std::ostringstream out;
    out<<"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Driver Readiness Inspector</title>"
       <<"<style>body{background:#11151e;color:#f2f6ff;font:15px system-ui;margin:32px auto;padding:0 24px;max-width:1250px}h1{font-size:30px}h2{color:#3070ff}table{width:100%;border-collapse:collapse;background:#1c222f}th,td{padding:10px;text-align:left;border-bottom:1px solid #11151e;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1c222f;padding:16px;border-radius:8px}details{margin:12px 0}summary{cursor:pointer;color:#3070ff}p{line-height:1.6}</style>"
       <<"<h1>Driver Readiness Inspector</h1><p>"<<HtmlEscape(report.value("created_utc", ""))<<" | Read-only support snapshot</p><pre>"<<HtmlEscape(Summary(report))<<"</pre>"
       <<"<h2>Present device nodes</h2><p>These are Windows PnP nodes, not a count of physical devices. Filter names below are registry metadata, not a verified attachment order.</p><table><thead><tr><th>Device</th><th>Class</th><th>Service</th><th>PnP</th></tr></thead><tbody>";
    for(const auto& d:report.at("devices")) {
        const auto& p=d.at("pnp");std::string label=p.value("status", "unknown");
        if(label=="known") label=std::to_string(p.at("value").value("problem",0u));
        out<<"<tr><td>"<<HtmlEscape(d.value("name", ""))<<"</td><td>"<<HtmlEscape(d.value("class", ""))<<"</td><td>"<<HtmlEscape(d.value("service", ""))<<"</td><td>"<<HtmlEscape(label)<<"</td></tr>";
    }
    out<<"</tbody></table><h2>Driver/service evidence</h2><p>Embedded-signature checks are offline, use cached trust only, and do not search package catalogs. A file without an embedded signature may be validly catalog signed. No result here proves that Windows blocked it.</p>";
    for(const auto& d:report.at("drivers"))out<<"<details><summary>"<<HtmlEscape(d.value("service", ""))<<"</summary><pre>"<<HtmlEscape(d.dump(2, ' ', false, Json::error_handler_t::replace))<<"</pre></details>";
    out<<"<h2>Device details</h2>";
    for(const auto& d:report.at("devices"))out<<"<details><summary>"<<HtmlEscape(d.value("name", ""))<<"</summary><pre>"<<HtmlEscape(d.dump(2, ' ', false, Json::error_handler_t::replace))<<"</pre></details>";
    out<<"<h2>Recent Code Integrity evidence</h2><p>Events can refer to historical or unrelated software. They do not establish the cause of a current device problem. Raw event XML is opt-in because it can contain identifiers and private paths.</p><pre>"<<HtmlEscape(report.at("code_integrity").dump(2, ' ', false, Json::error_handler_t::replace))<<"</pre>"
       <<"<h2>Collection limits and errors</h2><pre>"<<HtmlEscape(report.at("collection").dump(2))<<"</pre><p>For OEM deployment and support, add <strong>titancsa</strong> on Discord. No data is uploaded by this program.</p></html>";
    return out.str();
}
Json Preview() {
    Json d={{"id","device_0001"},{"name","Example USB controller [offline sample]"},{"class","HIDClass"},{"service","ExampleFilter"},{"pnp",Value("known",{{"problem",28},{"devnode_status",0}})},
        {"driver_package",{{"provider",Value("known","Example Manufacturer")},{"version",Value("known","1.0.0.0")},{"inf",Value("known","oem42.inf")}}},
        {"device_upper_filters",Value("known",Json::array({"ExampleFilter"}))},{"device_lower_filters",Value("not_present",nullptr)},
        {"class_upper_filters",Value("not_present",nullptr)},{"class_lower_filters",Value("not_present",nullptr)}};
    return {{"schema",1},{"tool",{{"name","Driver-Readiness-Inspector"},{"version","0.1.0"}}},{"created_utc","Offline demonstration data"},
        {"scope",{{"read_only",true},{"preview",true},{"include_sensitive",false}}},
        {"system",{{"os",Value("known",{{"build",26100},{"major",10},{"minor",0}})},{"secure_boot",Value("known","enabled")},{"hvci_running",Value("unknown",nullptr,5,"Illustrative access-denied observation; unknown is not incompatible.")}}},
        {"devices",Json::array({d})},{"drivers",Json::array({{{"service","ExampleFilter"},{"state",Value("known","stopped")},{"embedded_signature",Value("no_embedded_signature",nullptr,0,"Catalog signature has not been checked; no blocking conclusion.")}}})},
        {"code_integrity",{{"status","not_requested"},{"entries",Json::array()}}},
        {"collection",{{"device_limit",512},{"events_limit",64},{"truncated_devices",false},{"warnings",Json::array({"Offline sample only. No Windows device inventory was collected."})}}}};
}
bool WriteReport(const std::wstring& path, const std::string& bytes, std::string& error) {
    const HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE){error="Cannot create a new report (Windows error "+std::to_string(GetLastError())+"). Existing files are preserved; choose a new filename.";return false;}
    bool ok=true;std::size_t at=0;
    while(at<bytes.size()){DWORD done=0;const DWORD part=static_cast<DWORD>(std::min<std::size_t>(bytes.size()-at,1024*1024));
        if(!WriteFile(file,bytes.data()+at,part,&done,nullptr)||done==0){error="Report write failed (Windows error "+std::to_string(GetLastError())+"). The partial file was removed.";ok=false;break;}at+=done;}
    if(ok&&!FlushFileBuffers(file)){error="Report flush failed (Windows error "+std::to_string(GetLastError())+"). The partial file was removed.";ok=false;}
    CloseHandle(file);if(!ok)DeleteFileW(path.c_str());return ok;
}
}
