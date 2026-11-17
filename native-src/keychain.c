// Narrow Keychain bridge. Secret values travel only over stdin/stdout pipes.
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static void wipe(void *p,size_t n){volatile unsigned char *b=p;while(n--)*b++=0;}
int main(int argc, char **argv) {
    if(argc!=3 || (strcmp(argv[2],"google-client") && strcmp(argv[2],"google-session") && strcmp(argv[2],"self-test")))return 1;
    CFStringRef account=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);
    CFMutableDictionaryRef q=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q,kSecClass,kSecClassGenericPassword);
    CFDictionarySetValue(q,kSecAttrService,CFSTR("dev.hybridmail.google-oauth"));
    CFDictionarySetValue(q,kSecAttrAccount,account);
    OSStatus status=errSecParam;
    if(!strcmp(argv[1],"get")){
        CFDictionarySetValue(q,kSecReturnData,kCFBooleanTrue);
        CFDictionarySetValue(q,kSecMatchLimit,kSecMatchLimitOne);
        CFTypeRef result=NULL;status=SecItemCopyMatching(q,&result);
        if(status==errSecSuccess){CFDataRef data=(CFDataRef)result;fwrite(CFDataGetBytePtr(data),1,CFDataGetLength(data),stdout);CFRelease(data);}
    }else if(!strcmp(argv[1],"delete")){
        status=SecItemDelete(q);if(status==errSecItemNotFound)status=errSecSuccess;
    }else if(!strcmp(argv[1],"put")){
        unsigned char bytes[65537];size_t size=fread(bytes,1,sizeof(bytes),stdin);
        if(size==0||size>65536){wipe(bytes,sizeof(bytes));return 1;}
        CFDataRef data=CFDataCreate(NULL,bytes,size);wipe(bytes,sizeof(bytes));
        CFMutableDictionaryRef attrs=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(attrs,kSecValueData,data);
        status=SecItemUpdate(q,attrs);
        if(status==errSecItemNotFound){CFDictionarySetValue(q,kSecValueData,data);CFDictionarySetValue(q,kSecAttrLabel,CFSTR("Hybrid Mail Google OAuth"));status=SecItemAdd(q,NULL);}
        CFRelease(attrs);CFRelease(data);
    }
    CFRelease(q);CFRelease(account);
    if(status==errSecItemNotFound)return 2;
    if(status!=errSecSuccess){fprintf(stderr,"Keychain operation failed (%d)\n",(int)status);return 1;}
    return 0;
}
