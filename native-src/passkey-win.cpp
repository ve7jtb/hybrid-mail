// Native Windows PRF assertion helper. No registration, PIN handling or files.
// Public request metadata arrives on stdin. The PRF result returns only on stdout.
// Protocol: PQPRF001, provider byte (1=security key,2=platform), challenge[32],
// raw PRF salt[32], uint16be credential length + bytes, uint16be UTF-8 name + bytes.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <webauthn.h>
#include <io.h>
#include <fcntl.h>
#include <thread>
#ifndef WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6
#error A Windows SDK with WebAuthn PRF assertion support is required
#endif
#endif

namespace pqpasskey {
using Bytes = std::vector<unsigned char>;
static constexpr size_t MAX_REQUEST = 4096;
struct Request {
    unsigned char provider = 0;
    std::array<unsigned char,32> challenge{}, salt{};
    Bytes credential;
    std::string name;
};
static void wipe(void* data,size_t size) { volatile unsigned char* p=static_cast<volatile unsigned char*>(data);while(size--)*p++=0; }
static void check(bool ok) { if(!ok)throw std::runtime_error("Invalid native passkey request"); }
static bool validName(const std::string& name) {
    size_t i=0,count=0;
    while(i<name.size()) {
        uint32_t c=static_cast<unsigned char>(name[i++]), minimum=0;unsigned extra=0;
        if(c>=0xc2&&c<=0xdf){c&=31;extra=1;minimum=0x80;}
        else if(c>=0xe0&&c<=0xef){c&=15;extra=2;minimum=0x800;}
        else if(c>=0xf0&&c<=0xf4){c&=7;extra=3;minimum=0x10000;}
        else if(c>=0x80)return false;
        for(unsigned k=0;k<extra;k++){if(i>=name.size())return false;auto b=static_cast<unsigned char>(name[i++]);if((b&0xc0)!=0x80)return false;c=(c<<6)|(b&63);}
        if(c<minimum||c>0x10ffff||(c>=0xd800&&c<=0xdfff)||c<32||(c>=127&&c<=159))return false;
        if(++count>80)return false;
    }
    return count>0;
}
static Request parse(const Bytes& data) {
    check(data.size()>=77&&data.size()<=MAX_REQUEST&&std::memcmp(data.data(),"PQPRF001",8)==0);
    Request r;r.provider=data[8];check(r.provider==1||r.provider==2);
    std::copy_n(data.begin()+9,32,r.challenge.begin());std::copy_n(data.begin()+41,32,r.salt.begin());size_t pos=73;
    auto field=[&](size_t max){check(pos+2<=data.size());size_t n=(size_t(data[pos])<<8)|data[pos+1];pos+=2;check(n<=max&&n<=data.size()-pos);Bytes out(data.begin()+pos,data.begin()+pos+n);pos+=n;return out;};
    r.credential=field(2048);auto name=field(320);r.name.assign(name.begin(),name.end());check(pos==data.size()&&validName(r.name));return r;
}
static std::string b64(const unsigned char* data,size_t size) {
    static const char chars[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    check(size==0||data!=nullptr);std::string out;out.reserve((size*4+2)/3);
    for(size_t i=0;i<size;i+=3){uint32_t n=uint32_t(data[i])<<16;if(i+1<size)n|=uint32_t(data[i+1])<<8;if(i+2<size)n|=data[i+2];out+=chars[(n>>18)&63];out+=chars[(n>>12)&63];if(i+1<size)out+=chars[(n>>6)&63];if(i+2<size)out+=chars[n&63];}return out;
}
static std::string clientData(const Request& r) {return "{\"type\":\"webauthn.get\",\"challenge\":\""+b64(r.challenge.data(),32)+"\",\"origin\":\"https://ve7jtb.github.io\",\"crossOrigin\":false}";}
static bool supportsPrf(unsigned apiVersion){return apiVersion>=4;}
static int selfTest() {
    Bytes data={'P','Q','P','R','F','0','0','1',1};for(unsigned i=0;i<64;i++)data.push_back(static_cast<unsigned char>(i));
    data.insert(data.end(),{0,3,1,2,3,0,4,'T','e','s','t'});
    auto r=parse(data);check(r.provider==1&&r.credential==Bytes({1,2,3})&&r.salt[0]==32&&r.challenge[31]==31&&r.name=="Test");
    check(b64(r.credential.data(),3)=="AQID"&&b64(r.credential.data(),1)=="AQ"&&b64(r.credential.data(),2)=="AQI");
    check(clientData(r).find("https://ve7jtb.github.io")!=std::string::npos&&supportsPrf(4)&&supportsPrf(9)&&!supportsPrf(3));
    for(size_t n=0;n<data.size();n++){try{parse(Bytes(data.begin(),data.begin()+n));throw 1;}catch(const std::runtime_error&) {}}
    for(size_t offset:{size_t(0),size_t(8),size_t(73),size_t(74),size_t(78),size_t(79),size_t(80)}){auto bad=data;bad[offset]=255;try{parse(bad);throw 1;}catch(const std::runtime_error&) {}}
    auto extra=data;extra.push_back(0);try{parse(extra);throw 1;}catch(const std::runtime_error&) {}
    check(!validName("\n")&&!validName(std::string("\xc0\xaf",2))&&!validName(std::string("\xed\xa0\x80",3))&&validName("Backup key"));
    std::puts("PASS Windows passkey protocol, bounds, UTF-8, PRF API gate, unchanged salt, fixed RP and base64url; no authenticator accessed");return 0;
}

#ifdef _WIN32
struct Api {
    HMODULE library=nullptr;
    decltype(&WebAuthNGetApiVersionNumber) version=nullptr;
    decltype(&WebAuthNAuthenticatorGetAssertion) assertion=nullptr;
    decltype(&WebAuthNFreeAssertion) freeAssertion=nullptr;
    decltype(&WebAuthNGetCancellationId) cancellationId=nullptr;
    decltype(&WebAuthNCancelCurrentOperation) cancel=nullptr;
    explicit Api(bool load=true){
        if(!load)return;
        // Never load an application-local DLL with this security-sensitive name.
        library=LoadLibraryExW(L"webauthn.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!library)return;
        version=reinterpret_cast<decltype(version)>(GetProcAddress(library,"WebAuthNGetApiVersionNumber"));
        assertion=reinterpret_cast<decltype(assertion)>(GetProcAddress(library,"WebAuthNAuthenticatorGetAssertion"));
        freeAssertion=reinterpret_cast<decltype(freeAssertion)>(GetProcAddress(library,"WebAuthNFreeAssertion"));
        cancellationId=reinterpret_cast<decltype(cancellationId)>(GetProcAddress(library,"WebAuthNGetCancellationId"));
        cancel=reinterpret_cast<decltype(cancel)>(GetProcAddress(library,"WebAuthNCancelCurrentOperation"));
    }
    bool ready()const{return version&&assertion&&freeAssertion&&cancellationId&&cancel&&supportsPrf(version());}
    ~Api(){if(library)FreeLibrary(library);}
};
struct Operation {
    Api& api;Request& request;GUID cancellation{};HRESULT status=E_FAIL;PWEBAUTHN_ASSERTION result=nullptr;std::string client;
    Operation(Api& a,Request& r):api(a),request(r),client(clientData(r)){}
    ~Operation(){if(result){if(result->dwVersion>=3&&result->pHmacSecret){auto secret=result->pHmacSecret;if(secret->pbFirst)wipe(secret->pbFirst,secret->cbFirst);if(secret->pbSecond)wipe(secret->pbSecond,secret->cbSecond);}api.freeAssertion(result);}}
};
static WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options(Request& r,GUID& cancellation,WEBAUTHN_CREDENTIAL& credential,WEBAUTHN_HMAC_SECRET_SALT& salt,WEBAUTHN_HMAC_SECRET_SALT_VALUES& salts){
    credential={WEBAUTHN_CREDENTIAL_CURRENT_VERSION,static_cast<DWORD>(r.credential.size()),r.credential.data(),WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY};
    salt={32,r.salt.data(),0,nullptr};salts={&salt,0,nullptr};
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS o{};o.dwVersion=WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;o.dwTimeoutMilliseconds=290000;
    if(!r.credential.empty()){o.CredentialList.cCredentials=1;o.CredentialList.pCredentials=&credential;}
    o.dwAuthenticatorAttachment=r.provider==1?WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM:WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    o.dwUserVerificationRequirement=WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;o.pCancellationId=&cancellation;o.pHmacSecretSaltValues=&salts;
    // dwFlags stays zero: the API performs WebAuthn PRF domain separation. Do NOT
    // set WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG (that means raw CTAP salts).
    return o;
}
static LRESULT CALLBACK windowProc(HWND window,UINT message,WPARAM w,LPARAM l){
    auto op=reinterpret_cast<Operation*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_CLOSE||(message==WM_COMMAND&&LOWORD(w)==1)){if(op){op->api.cancel(&op->cancellation);EnableWindow(GetDlgItem(window,1),FALSE);}return 0;}
    if(message==WM_APP+1){DestroyWindow(window);return 0;}
    if(message==WM_DESTROY){PostQuitMessage(0);return 0;}
    return DefWindowProcW(window,message,w,l);
}
static std::string resultJson(Operation& op);
static void WINAPI freeSyntheticAssertion(PWEBAUTHN_ASSERTION){}
static int nativeSelfTest(){
    selfTest();Request r;r.provider=1;r.credential={1,2,3};GUID id{};WEBAUTHN_CREDENTIAL credential{};WEBAUTHN_HMAC_SECRET_SALT salt{};WEBAUTHN_HMAC_SECRET_SALT_VALUES salts{};
    auto o=options(r,id,credential,salt,salts);check(o.dwVersion==6&&o.dwFlags==0&&o.dwUserVerificationRequirement==WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED&&o.CredentialList.cCredentials==1&&o.pHmacSecretSaltValues->pGlobalHmacSalt->pbFirst==r.salt.data()&&o.dwAuthenticatorAttachment==WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM);
    r.provider=2;r.credential.clear();o=options(r,id,credential,salt,salts);check(o.CredentialList.cCredentials==0&&o.dwAuthenticatorAttachment==WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM);
    Api synthetic(false);synthetic.freeAssertion=freeSyntheticAssertion;
    unsigned char secretBytes[32]={1},auth[37]={},signature[64]={},credentialId[3]={1,2,3};WEBAUTHN_HMAC_SECRET_SALT secret{32,secretBytes,0,nullptr};WEBAUTHN_ASSERTION a{};
    a.dwVersion=3;a.pHmacSecret=&secret;a.Credential={1,3,credentialId,WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY};a.cbAuthenticatorData=37;a.pbAuthenticatorData=auth;a.cbSignature=64;a.pbSignature=signature;
    {Operation op(synthetic,r);op.result=&a;auto json=resultJson(op);check(json.find("\"rawId\":\"AQID\"")!=std::string::npos&&json.find("\"first\":\"AQAAA")!=std::string::npos);wipe(json.data(),json.size());
     r.credential={4};try{resultJson(op);throw 1;}catch(const std::runtime_error&){}r.credential.clear();
     secret.cbFirst=31;try{resultJson(op);throw 1;}catch(const std::runtime_error&){}secret.cbFirst=32;}
    check(secretBytes[0]==0);
    std::puts("PASS Windows SDK assertion options, required UV, PRF preprocessing, provider/discovery, result encoding, wrong-key/missing-PRF rejection and output clearing; no UI requested");return 0;
}
static std::string resultJson(Operation& op){
    auto a=op.result;
    check(a&&a->dwVersion>=3&&a->pHmacSecret&&a->pHmacSecret->cbFirst==32&&a->pHmacSecret->pbFirst);
    check(a->Credential.cbId>0&&a->Credential.cbId<=2048&&a->Credential.pbId&&a->cbAuthenticatorData>=37&&a->cbAuthenticatorData<=16384&&a->pbAuthenticatorData&&a->cbSignature>0&&a->cbSignature<=16384&&a->pbSignature&&a->cbUserId<=64);
    check(op.request.credential.empty()||(a->Credential.cbId==op.request.credential.size()&&std::memcmp(a->Credential.pbId,op.request.credential.data(),a->Credential.cbId)==0));
    // Java also checks challenge/origin/RP hash/UP/UV before unwrapping the vault.
    auto prf=b64(a->pHmacSecret->pbFirst,32);
    std::string out="{\"type\":\"public-key\",\"rawId\":\""+b64(a->Credential.pbId,a->Credential.cbId)+"\",\"response\":{\"authenticatorData\":\""+b64(a->pbAuthenticatorData,a->cbAuthenticatorData)+"\",\"clientDataJSON\":\""+b64(reinterpret_cast<const unsigned char*>(op.client.data()),op.client.size())+"\",\"signature\":\""+b64(a->pbSignature,a->cbSignature)+"\",\"userHandle\":\""+b64(a->pbUserId,a->cbUserId)+"\"},\"clientExtensionResults\":{\"prf\":{\"results\":{\"first\":\""+prf+"\"}}}}";
    wipe(prf.data(),prf.size());return out;
}
static int run(Request& r,Api& api){
    Operation op(api,r);if(FAILED(api.cancellationId(&op.cancellation)))throw std::runtime_error("Cannot create WebAuthn cancellation context");
    HINSTANCE instance=GetModuleHandleW(nullptr);WNDCLASSW wc{};wc.lpfnWndProc=windowProc;wc.hInstance=instance;wc.lpszClassName=L"PQMailPasskey";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc))throw std::runtime_error("Cannot create native passkey window");
    HWND window=CreateWindowExW(0,wc.lpszClassName,L"PQ Mail — unlock with passkey",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,CW_USEDEFAULT,CW_USEDEFAULT,520,185,nullptr,nullptr,instance,nullptr);
    if(!window)throw std::runtime_error("Cannot create native passkey window");SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(&op));
    int length=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,r.name.data(),static_cast<int>(r.name.size()),nullptr,0);check(length>0);std::wstring name(length,L' ');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,r.name.data(),static_cast<int>(r.name.size()),name.data(),length);
    std::wstring label=L"Use your existing PQ Mail passkey: "+name+L"\nApprove the Windows prompt. No new credential is created.";
    CreateWindowW(L"STATIC",label.c_str(),WS_CHILD|WS_VISIBLE,18,18,475,65,window,nullptr,instance,nullptr);CreateWindowW(L"BUTTON",L"Cancel",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,385,95,100,28,window,reinterpret_cast<HMENU>(1),instance,nullptr);ShowWindow(window,SW_SHOW);SetForegroundWindow(window);
    std::thread worker([&]{WEBAUTHN_CLIENT_DATA client{WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,static_cast<DWORD>(op.client.size()),reinterpret_cast<PBYTE>(op.client.data()),WEBAUTHN_HASH_ALGORITHM_SHA_256};WEBAUTHN_CREDENTIAL credential{};WEBAUTHN_HMAC_SECRET_SALT salt{};WEBAUTHN_HMAC_SECRET_SALT_VALUES salts{};auto o=options(r,op.cancellation,credential,salt,salts);op.status=api.assertion(window,L"ve7jtb.github.io",&client,&o,&op.result);PostMessageW(window,WM_APP+1,0,0);});
    MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}worker.join();
    if(FAILED(op.status)){char error[180];std::snprintf(error,sizeof(error),"{\"error\":\"Windows WebAuthn failed (HRESULT 0x%08lX). Cancelled, unavailable, or unsupported PRF; vault remains locked.\"}",static_cast<unsigned long>(op.status));std::fputs(error,stdout);return 2;}
    if(!op.result||op.result->dwVersion<3||!op.result->pHmacSecret||op.result->pHmacSecret->cbFirst!=32){std::fputs("{\"error\":\"This authenticator did not return PRF output. Vault remains locked; no browser was opened.\"}",stdout);return 2;}
    auto output=resultJson(op);bool ok=std::fwrite(output.data(),1,output.size(),stdout)==output.size()&&std::fflush(stdout)==0;wipe(output.data(),output.size());return ok?0:2;
}
#endif
} // namespace

int main(int argc,char** argv){
    using namespace pqpasskey;
    try{
        if(argc==2&&std::strcmp(argv[1],"--self-test")==0){
#ifdef _WIN32
            return nativeSelfTest();
#else
            return selfTest();
#endif
        }
        if(argc==2&&std::strcmp(argv[1],"--probe")==0){
#ifdef _WIN32
            Api api;std::printf("{\"available\":%s,\"apiVersion\":%lu}",api.ready()?"true":"false",api.version?static_cast<unsigned long>(api.version()):0UL);return 0;
#else
            std::puts("{\"available\":false,\"apiVersion\":0}");return 0;
#endif
        }
        check(argc==1);
#ifdef _WIN32
        _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
#endif
        Bytes data(MAX_REQUEST+1);size_t size=std::fread(data.data(),1,data.size(),stdin);check(!std::ferror(stdin)&&size<=MAX_REQUEST);data.resize(size);auto request=parse(data);
#ifdef _WIN32
        Api api;if(!api.ready()){std::fputs("{\"error\":\"Windows WebAuthn PRF API v4 or later is required. Choose Browser in Keys → Passkey method; no browser was opened.\"}",stdout);return 2;}return run(request,api);
#else
        (void)request;throw std::runtime_error("Native Windows passkeys require Windows");
#endif
    }catch(...){std::fputs("{\"error\":\"Invalid or incomplete native passkey operation; vault remains locked\"}",stdout);return 1;}
}
