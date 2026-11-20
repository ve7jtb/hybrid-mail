// Narrow Keychain bridge. Secrets travel only over stdin/stdout pipes.
#include <Security/Security.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdio.h>
#include <string.h>
static void wipe(void *p,size_t n){volatile unsigned char *b=p;while(n--)*b++=0;}
static CFMutableDictionaryRef query(CFStringRef account,Boolean protected){
    CFMutableDictionaryRef q=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q,kSecClass,kSecClassGenericPassword);
    CFDictionarySetValue(q,kSecAttrService,CFSTR("dev.hybridmail.google-oauth"));
    CFDictionarySetValue(q,kSecAttrAccount,account);
    if(protected)CFDictionarySetValue(q,kSecUseDataProtectionKeychain,kCFBooleanTrue);
    return q;
}
static OSStatus readItem(CFStringRef account,Boolean protected,Boolean noUI,CFDataRef *data){
    CFMutableDictionaryRef q=query(account,protected);
    CFDictionarySetValue(q,kSecReturnData,kCFBooleanTrue);
    CFDictionarySetValue(q,kSecMatchLimit,kSecMatchLimitOne);
    LAContext *context=nil;
    if(noUI){context=[[LAContext alloc] init];context.interactionNotAllowed=YES;CFDictionarySetValue(q,kSecUseAuthenticationContext,(__bridge CFTypeRef)context);}
    OSStatus s=SecItemCopyMatching(q,(CFTypeRef*)data);CFRelease(q);return s;
}
static OSStatus removeItem(CFStringRef account,Boolean protected){
    CFMutableDictionaryRef q=query(account,protected);OSStatus s=SecItemDelete(q);CFRelease(q);return s==errSecItemNotFound?errSecSuccess:s;
}
static OSStatus writeItem(CFStringRef account,Boolean protected,CFDataRef data){
    CFMutableDictionaryRef q=query(account,protected);
    CFMutableDictionaryRef attrs=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs,kSecValueData,data);
    OSStatus s=SecItemUpdate(q,attrs);
    if(s==errSecItemNotFound){
        CFDictionarySetValue(q,kSecValueData,data);CFDictionarySetValue(q,kSecAttrLabel,(CFEqual(account,CFSTR("microsoft-session"))?CFSTR("PQ Mail Microsoft OAuth refresh token"):CFSTR("PQ Mail Google OAuth refresh token")));
        if(protected){
            CFErrorRef error=NULL;
            SecAccessControlRef acl=SecAccessControlCreateWithFlags(NULL,kSecAttrAccessibleWhenUnlockedThisDeviceOnly,kSecAccessControlUserPresence,&error);
            if(!acl){if(error)CFRelease(error);CFRelease(q);CFRelease(attrs);return errSecParam;}
            CFDictionarySetValue(q,kSecAttrAccessControl,acl);CFRelease(acl);
        }
        s=SecItemAdd(q,NULL);
    }
    CFRelease(q);CFRelease(attrs);return s;
}
int main(int argc,char **argv){@autoreleasepool {
    if(argc!=3 || (strcmp(argv[2],"google-client") && strcmp(argv[2],"google-session") && strcmp(argv[2],"microsoft-session") && strcmp(argv[2],"self-test")))return 1;
    CFStringRef account=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);
    const char *op=argv[1];OSStatus s=errSecParam;CFDataRef data=NULL;
    if(!strcmp(op,"get") || !strcmp(op,"get-protected") || !strcmp(op,"probe-protected")){
        s=readItem(account,strcmp(op,"get")!=0,!strcmp(op,"probe-protected"),&data);
        if(s==errSecSuccess && strcmp(op,"probe-protected"))fwrite(CFDataGetBytePtr(data),1,CFDataGetLength(data),stdout);
    }else if(!strcmp(op,"delete") || !strcmp(op,"delete-protected"))s=removeItem(account,!strcmp(op,"delete-protected"));
    else if(!strcmp(op,"put") || !strcmp(op,"put-protected")){
        unsigned char bytes[65537];size_t size=fread(bytes,1,sizeof(bytes),stdin);
        if(size>0 && size<=65536){data=CFDataCreate(NULL,bytes,size);s=writeItem(account,!strcmp(op,"put-protected"),data);}wipe(bytes,sizeof(bytes));
    }else if(!strcmp(op,"protect") || !strcmp(op,"unprotect")){
        Boolean dest=!strcmp(op,"protect");s=readItem(account,!dest,false,&data);
        if(s==errSecSuccess){
            s=writeItem(account,dest,data);
            if(s==errSecSuccess){CFDataRef check=NULL;s=readItem(account,dest,false,&check);
                if(s==errSecSuccess && !CFEqual(data,check))s=errSecDecode;
                if(check)CFRelease(check);
                if(s==errSecSuccess)s=removeItem(account,!dest);
                else removeItem(account,dest); // Keep original if verification is cancelled or fails.
            }
        }
    }
    if(data)CFRelease(data);CFRelease(account);
    if(s==errSecItemNotFound)return 2;
    if(s==errSecInteractionNotAllowed)return 4;
    if(s==errSecUserCanceled || s==errSecAuthFailed)return 3;
    if(s!=errSecSuccess){fprintf(stderr,"Keychain operation failed (%d)\n",(int)s);return 1;}return 0;
}}
