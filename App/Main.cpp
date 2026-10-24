#include "Inspector.h"
#include <Windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

namespace {
constexpr COLORREF Bg=RGB(17,21,30),Panel=RGB(28,34,47),Fg=RGB(242,246,255),Blue=RGB(48,112,255);
enum {Refresh=100,ExportJson,ExportHtml,Discord,EventsOption,SensitiveOption,DeviceList,Details,Summary,Status};
constexpr UINT Complete=WM_APP+1;
HBRUSH bg=nullptr,panel=nullptr;HFONT font=nullptr,title=nullptr;
struct App {HWND window=nullptr;unsigned dpi=96;bool preview=false,busy=false,closing=false;std::atomic_bool stop{false};std::thread worker;std::mutex mutex;Inspector::Json pending,report;std::string failure;};
int Scale(const App& a,int n){return MulDiv(n,static_cast<int>(a.dpi),96);}
std::wstring Wide(const std::string& s) {if(s.empty())return {};int n=MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0);std::wstring w(static_cast<std::size_t>(n),0);MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),w.data(),n);return w;}
void Set(App& a,int id,const std::wstring& text){std::wstring windows;windows.reserve(text.size());for(std::size_t i=0;i<text.size();++i){if(text[i]==L'\n'&&(i==0||text[i-1]!=L'\r'))windows+=L'\r';windows+=text[i];}SetWindowTextW(GetDlgItem(a.window,id),windows.c_str());}
HWND Add(App& a,int id,const wchar_t* type,const wchar_t* text,DWORD style=0){auto h=CreateWindowExW(0,type,text,WS_CHILD|WS_VISIBLE|style,0,0,1,1,a.window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);SendMessageW(h,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);return h;}
void Place(App& a,int id,int x,int y,int w,int h){MoveWindow(GetDlgItem(a.window,id),Scale(a,x),Scale(a,y),Scale(a,w),Scale(a,h),TRUE);}
void Layout(App& a){RECT r{};GetClientRect(a.window,&r);const int w=MulDiv(r.right,96,static_cast<int>(a.dpi)),h=MulDiv(r.bottom,96,static_cast<int>(a.dpi));
    Place(a,Refresh,26,96,112,38);Place(a,ExportJson,148,96,124,38);Place(a,ExportHtml,282,96,124,38);Place(a,Discord,w-216,96,190,38);
    Place(a,EventsOption,26,147,278,26);Place(a,SensitiveOption,318,147,w-344,26);
    Place(a,Summary,26,190,w-52,124);const int left=(w-68)*44/100;
    Place(a,DeviceList,26,330,left,h-404);Place(a,Details,42+left,330,w-left-68,h-404);Place(a,Status,26,h-59,w-52,40);
}
void Columns(HWND list){for(const auto& pair:{std::pair<const wchar_t*,int>{L"Present device node",240},{L"Class",100},{L"Service",140},{L"PnP",75}}){LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH;c.pszText=const_cast<wchar_t*>(pair.first);c.cx=pair.second;ListView_InsertColumn(list,Header_GetItemCount(ListView_GetHeader(list)),&c);}}
void Selected(App& a){const auto list=GetDlgItem(a.window,DeviceList);const int selected=ListView_GetNextItem(list,-1,LVNI_SELECTED);if(selected<0||static_cast<std::size_t>(selected)>=a.report.at("devices").size())return;
    const auto& device=a.report.at("devices")[static_cast<std::size_t>(selected)];std::string s=Inspector::DeviceSummary(device);
    std::set<std::string> services;services.insert(device.value("service",""));
    for(const auto key:{"device_upper_filters","device_lower_filters","class_upper_filters","class_lower_filters"})if(device.contains(key)&&device.at(key).value("status","")=="known"&&device.at(key).at("value").is_array())for(const auto& value:device.at(key).at("value"))if(value.is_string())services.insert(value.get<std::string>());
    for(const auto& driver:a.report.at("drivers"))if(services.count(driver.value("service","")))s+="\r\n\r\n"+Inspector::ServiceSummary(driver);
    Set(a,Details,Wide(s));
}
void Populate(App& a){auto list=GetDlgItem(a.window,DeviceList);SendMessageW(list,WM_SETREDRAW,FALSE,0);ListView_DeleteAllItems(list);
    int row=0;for(const auto& d:a.report.at("devices")){const auto name=Wide(d.value("name","Unnamed"));LVITEMW item{};item.mask=LVIF_TEXT;item.iItem=row;item.pszText=const_cast<wchar_t*>(name.c_str());ListView_InsertItem(list,&item);
        const auto type=Wide(d.value("class","unknown")),service=Wide(d.value("service",""));ListView_SetItemText(list,row,1,const_cast<wchar_t*>(type.c_str()));ListView_SetItemText(list,row,2,const_cast<wchar_t*>(service.c_str()));
        auto state=d.at("pnp").value("status","unknown");if(state=="known")state=std::to_string(d.at("pnp").at("value").value("problem",0u));const auto value=Wide(state);ListView_SetItemText(list,row,3,const_cast<wchar_t*>(value.c_str()));++row;}
    SendMessageW(list,WM_SETREDRAW,TRUE,0);InvalidateRect(list,nullptr,FALSE);Set(a,Summary,Wide(Inspector::Summary(a.report)));
    Set(a,Status,a.preview?L"OFFLINE PREVIEW | Illustrative data. No device APIs were called.":L"Snapshot complete. Select a Windows device node for details. Reports never change drivers or security settings.");
    if(row){ListView_SetItemState(list,0,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);Selected(a);}
}
void Busy(App& a,bool value){a.busy=value;for(const auto id:{Refresh,ExportJson,ExportHtml,EventsOption,SensitiveOption})EnableWindow(GetDlgItem(a.window,id),!value);}
void Begin(App& a){if(a.busy)return;if(a.worker.joinable())a.worker.join();
    if(a.preview){a.report=Inspector::Preview();Populate(a);return;}
    Inspector::Options options;options.events=SendDlgItemMessageW(a.window,EventsOption,BM_GETCHECK,0,0)==BST_CHECKED;options.include_sensitive=SendDlgItemMessageW(a.window,SensitiveOption,BM_GETCHECK,0,0)==BST_CHECKED;options.stop=&a.stop;
    a.stop=false;Busy(a,true);Set(a,Status,L"Reading Windows inventory and cached binary evidence in the background. No installation or input capture...");
    try{a.worker=std::thread([&a,options]{try{auto report=Inspector::Collect(options);{std::lock_guard<std::mutex> lock(a.mutex);a.pending=std::move(report);a.failure.clear();}}catch(const std::exception& e){std::lock_guard<std::mutex> lock(a.mutex);a.failure=e.what();}catch(...){std::lock_guard<std::mutex> lock(a.mutex);a.failure="Unexpected collection failure; no changes were made.";}PostMessageW(a.window,Complete,0,0);});}catch(const std::exception& e){Busy(a,false);Set(a,Status,Wide(std::string("Cannot start collection: ")+e.what()));}
}
void Save(App& a,bool html){if(a.busy||a.report.empty())return;wchar_t path[32768]{};wcscpy_s(path,html?L"Driver-Readiness-Report.html":L"Driver-Readiness-Report.json");OPENFILENAMEW dialog{sizeof(dialog)};dialog.hwndOwner=a.window;dialog.lpstrFile=path;dialog.nMaxFile=32768;dialog.lpstrFilter=html?L"HTML report\0*.html\0\0":L"JSON report\0*.json\0\0";dialog.lpstrDefExt=html?L"html":L"json";dialog.Flags=OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;
    if(!GetSaveFileNameW(&dialog))return;std::string error;try{if(!Inspector::WriteReport(path,html?Inspector::Html(a.report):Inspector::JsonText(a.report),error)){Set(a,Status,Wide(error));return;}}catch(const std::exception& e){Set(a,Status,Wide(e.what()));return;}Set(a,Status,L"Report saved locally. Review Windows labels before sharing; this app never uploads reports.");
}
void CopyDiscord(App& a){if(!OpenClipboard(a.window))return;EmptyClipboard();const wchar_t handle[]=L"titancsa";const auto memory=GlobalAlloc(GMEM_MOVEABLE,sizeof(handle));if(memory){if(auto p=GlobalLock(memory)){memcpy(p,handle,sizeof(handle));GlobalUnlock(memory);if(!SetClipboardData(CF_UNICODETEXT,memory))GlobalFree(memory);}else GlobalFree(memory);}CloseClipboard();Set(a,Status,L"Discord handle copied: titancsa. Mention OEM driver deployment / Driver-Readiness-Inspector.");}
void Fonts(App& a){font=CreateFontW(-Scale(a,14),0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");title=CreateFontW(-Scale(a,28),0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");}
LRESULT CALLBACK Proc(HWND w,UINT m,WPARAM p,LPARAM l){auto a=reinterpret_cast<App*>(GetWindowLongPtrW(w,GWLP_USERDATA));if(m==WM_NCCREATE){a=static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);a->window=w;SetWindowLongPtrW(w,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(a));}if(!a)return DefWindowProcW(w,m,p,l);
    switch(m){
    case WM_CREATE:{a->dpi=GetDpiForWindow(w);Fonts(*a);BOOL dark=TRUE;DwmSetWindowAttribute(w,20,&dark,sizeof(dark));
        for(const auto& pair:{std::pair<int,const wchar_t*>{Refresh,L"Refresh"},{ExportJson,L"Export JSON"},{ExportHtml,L"Export HTML"},{Discord,L"Copy Discord handle"}})Add(*a,pair.first,L"BUTTON",pair.second,BS_OWNERDRAW|WS_TABSTOP);
        Add(*a,EventsOption,L"BUTTON",L"Include recent Code Integrity errors",BS_AUTOCHECKBOX|WS_TABSTOP);Add(*a,SensitiveOption,L"BUTTON",L"Include raw device IDs, full paths and event XML",BS_AUTOCHECKBOX|WS_TABSTOP);
        SetWindowTheme(GetDlgItem(w,EventsOption),L"",L"");SetWindowTheme(GetDlgItem(w,SensitiveOption),L"",L"");
        Add(*a,Summary,L"EDIT",L"",ES_MULTILINE|ES_READONLY|WS_VSCROLL);auto list=Add(*a,DeviceList,WC_LISTVIEWW,L"",LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS|WS_TABSTOP|WS_VSCROLL);
        ListView_SetExtendedListViewStyle(list,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);ListView_SetBkColor(list,Panel);ListView_SetTextBkColor(list,Panel);ListView_SetTextColor(list,Fg);Columns(list);
        SetWindowTheme(list,L"DarkMode_Explorer",nullptr);Add(*a,Details,L"EDIT",L"Select a device for PnP, service and package evidence.",ES_MULTILINE|ES_READONLY|WS_VSCROLL|ES_AUTOVSCROLL);
        Add(*a,Status,L"STATIC",L"Ready.");Layout(*a);PostMessageW(w,WM_COMMAND,Refresh,0);return 0;}
    case WM_GETMINMAXINFO:{const auto info=reinterpret_cast<MINMAXINFO*>(l);info->ptMinTrackSize={Scale(*a,940),Scale(*a,700)};return 0;}
    case WM_SIZE:Layout(*a);return 0;
    case WM_DPICHANGED:{a->dpi=HIWORD(p);const auto f=font,t=title;Fonts(*a);EnumChildWindows(w,[](HWND child,LPARAM){SendMessageW(child,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);return TRUE;},0);DeleteObject(f);DeleteObject(t);const auto r=reinterpret_cast<RECT*>(l);SetWindowPos(w,nullptr,r->left,r->top,r->right-r->left,r->bottom-r->top,SWP_NOZORDER|SWP_NOACTIVATE);Layout(*a);return 0;}
    case WM_COMMAND:switch(LOWORD(p)){case Refresh:Begin(*a);break;case ExportJson:Save(*a,false);break;case ExportHtml:Save(*a,true);break;case Discord:CopyDiscord(*a);break;case SensitiveOption:if(SendDlgItemMessageW(w,SensitiveOption,BM_GETCHECK,0,0)==BST_CHECKED)Set(*a,Status,L"Sensitive export requested: the NEXT refresh includes instance IDs, complete binary paths and raw event XML. Review before sharing.");break;}return 0;
    case WM_NOTIFY:if(reinterpret_cast<NMHDR*>(l)->idFrom==DeviceList&&reinterpret_cast<NMHDR*>(l)->code==LVN_ITEMCHANGED)Selected(*a);return 0;
    case Complete:{if(a->worker.joinable())a->worker.join();Busy(*a,false);if(a->closing){DestroyWindow(w);return 0;}std::lock_guard<std::mutex> lock(a->mutex);if(a->failure.empty()){a->report=std::move(a->pending);Populate(*a);}else Set(*a,Status,Wide("Collection failed: "+a->failure));return 0;}
    case WM_CLOSE:if(a->busy){a->closing=true;a->stop=true;Set(*a,Status,L"Finishing the current read and closing safely...");return 0;}DestroyWindow(w);return 0;
    case WM_DESTROY:PostQuitMessage(0);return 0;
    case WM_SETCURSOR:if(LOWORD(l)==HTCLIENT){const auto h=reinterpret_cast<HWND>(p);wchar_t cls[32]{};GetClassNameW(h,cls,32);if(_wcsicmp(cls,L"BUTTON")==0&&IsWindowEnabled(h)){SetCursor(LoadCursorW(nullptr,IDC_HAND));return TRUE;}}break;
    case WM_CTLCOLORSTATIC:case WM_CTLCOLOREDIT:{const auto dc=reinterpret_cast<HDC>(p);SetTextColor(dc,Fg);SetBkColor(dc,m==WM_CTLCOLOREDIT?Panel:Bg);return reinterpret_cast<LRESULT>(m==WM_CTLCOLOREDIT?panel:bg);}
    case WM_DRAWITEM:{const auto d=reinterpret_cast<DRAWITEMSTRUCT*>(l);if(d->CtlType!=ODT_BUTTON)break;const bool primary=d->CtlID==Refresh;const HBRUSH brush=CreateSolidBrush(primary?Blue:Panel);FillRect(d->hDC,&d->rcItem,brush);DeleteObject(brush);SetBkMode(d->hDC,TRANSPARENT);SetTextColor(d->hDC,Fg);SelectObject(d->hDC,font);wchar_t text[128]{};GetWindowTextW(d->hwndItem,text,128);RECT r=d->rcItem;DrawTextW(d->hDC,text,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);if(d->itemState&ODS_FOCUS)DrawFocusRect(d->hDC,&r);return TRUE;}
    case WM_ERASEBKGND:return TRUE;
    case WM_PAINT:{PAINTSTRUCT ps{};const auto dc=BeginPaint(w,&ps);RECT r{};GetClientRect(w,&r);FillRect(dc,&r,bg);SetBkMode(dc,TRANSPARENT);SetTextColor(dc,Fg);SelectObject(dc,title);const wchar_t* heading=L"Driver Readiness Inspector";TextOutW(dc,Scale(*a,26),Scale(*a,22),heading,static_cast<int>(wcslen(heading)));SelectObject(dc,font);const wchar_t* sub=L"Read Windows evidence. Understand the next step. No new driver required.";TextOutW(dc,Scale(*a,27),Scale(*a,63),sub,static_cast<int>(wcslen(sub)));EndPaint(w,&ps);return 0;}
    }return DefWindowProcW(w,m,p,l);
}
void Console(const std::string& message){const HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);DWORD mode=0,done=0;if(output!=nullptr&&output!=INVALID_HANDLE_VALUE){if(GetConsoleMode(output,&mode)){auto w=Wide(message+"\n");WriteConsoleW(output,w.data(),static_cast<DWORD>(w.size()),&done,nullptr);}else {auto s=message+"\n";WriteFile(output,s.data(),static_cast<DWORD>(s.size()),&done,nullptr);}}}
int Cli(const std::vector<std::wstring>& args){bool self=false,preview=false,help=false;Inspector::Options options;std::wstring path;std::string format="json";
    for(std::size_t i=1;i<args.size();++i){if(args[i]==L"--self-test")self=true;else if(args[i]==L"--preview")preview=true;else if(args[i]==L"--events")options.events=true;else if(args[i]==L"--include-sensitive")options.include_sensitive=true;else if(args[i]==L"--help"||args[i]==L"-h")help=true;else if(args[i]==L"--report"&&i+1<args.size())path=args[++i];else if(args[i]==L"--format=json")format="json";else if(args[i]==L"--format=html")format="html";else{Console("Unknown or incomplete argument. Use --help.");return 2;}}
    if(help){Console("Driver Readiness Inspector 0.1.0\nRead-only; no driver required; no elevation requested.\n  --report NEW_PATH [--format=json|html] [--events] [--include-sensitive]\n  --preview --report NEW_PATH [--format=json|html]  (sample data, offline)\n  --self-test  (offline fixtures)\nWith no arguments: native graphical interface. --preview alone opens a sample interface.\nExisting report files are preserved. No report is uploaded. Unknown does not mean incompatible.");return 0;}
    if(self){std::string text;const bool ok=Inspector::SelfTest(text);Console(text);return ok?0:1;}
    if(path.empty()){Console("Missing --report NEW_PATH. Use --help.");return 2;}
    try{const auto report=preview?Inspector::Preview():Inspector::Collect(options);std::string error;if(!Inspector::WriteReport(path,format=="html"?Inspector::Html(report):Inspector::JsonText(report),error)){Console(error);return 1;}Console("Read-only report written. Review privacy and collection limits before sharing. No compatibility or certification verdict was issued.");return report.at("collection").contains("device_error")?3:0;}catch(const std::exception& e){Console(std::string("Report failed: ")+e.what());return 1;}
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int show){int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return 1;std::vector<std::wstring> args;for(int i=0;i<argc;++i)args.emplace_back(argv[i]);LocalFree(argv);
    bool gui=args.size()==1||(args.size()==2&&args[1]==L"--preview");if(!gui){AttachConsole(ATTACH_PARENT_PROCESS);return Cli(args);}
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);INITCOMMONCONTROLSEX common{sizeof(common),ICC_LISTVIEW_CLASSES};InitCommonControlsEx(&common);
    App app;app.preview=args.size()==2;bg=CreateSolidBrush(Bg);panel=CreateSolidBrush(Panel);WNDCLASSW cls{};cls.hInstance=instance;cls.lpfnWndProc=Proc;cls.lpszClassName=L"TitanDriverReadinessInspector";cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);cls.hbrBackground=bg;RegisterClassW(&cls);
    const auto dpi=GetDpiForSystem();const int width=std::min(MulDiv(1280,static_cast<int>(dpi),96),GetSystemMetrics(SM_CXSCREEN)-40),height=std::min(MulDiv(850,static_cast<int>(dpi),96),GetSystemMetrics(SM_CYSCREEN)-70);
    const auto window=CreateWindowExW(0,cls.lpszClassName,L"Driver Readiness Inspector | Titanfyre",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,width,height,nullptr,nullptr,instance,&app);if(!window)return 1;ShowWindow(window,show);UpdateWindow(window);
    MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){if(!IsDialogMessageW(window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
    app.stop=true;if(app.worker.joinable())app.worker.join();DeleteObject(font);DeleteObject(title);DeleteObject(panel);DeleteObject(bg);return static_cast<int>(message.wParam);
}
