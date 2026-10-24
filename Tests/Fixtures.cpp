#include "../App/Inspector.h"
#include <stdexcept>
#include <Windows.h>

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
        unsigned seed=0x12345678u;
        for(unsigned i=0;i<2000;++i){std::vector<std::uint8_t> bytes(i%128);for(auto& b:bytes){seed=seed*1664525u+1013904223u;b=static_cast<std::uint8_t>(seed>>24);}const auto observation=DecodeRegistryValue(i%4==0?REG_DWORD:i%4==1?REG_SZ:i%4==2?REG_MULTI_SZ:REG_BINARY,bytes);check(observation.contains("status")&&observation.contains("value")&&observation.contains("error"));}
        for(unsigned i=0;i<10000;++i){const std::string s="<>&\"'"+std::to_string(i);check(HtmlEscape(s).find('<')==std::string::npos);}
        result=std::to_string(checks)+" offline escaping/schema/status fixtures passed. No driver or device was opened.";return true;
    }catch(const std::exception& e){result=e.what();return false;}
}
}
