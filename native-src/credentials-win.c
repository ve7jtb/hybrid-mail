#include <windows.h>
#include <wincred.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
int main(int argc,char **argv){
 if(argc!=3||(strcmp(argv[2],"google-client")&&strcmp(argv[2],"google-session")&&strcmp(argv[2],"self-test")))return 1;
 _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
 char target[100];snprintf(target,sizeof(target),"dev.hybridmail.google-oauth/%s",argv[2]);
 if(!strcmp(argv[1],"get")){PCREDENTIALA c=NULL;if(!CredReadA(target,CRED_TYPE_GENERIC,0,&c))return GetLastError()==ERROR_NOT_FOUND?2:1;fwrite(c->CredentialBlob,1,c->CredentialBlobSize,stdout);CredFree(c);return 0;}
 if(!strcmp(argv[1],"delete"))return CredDeleteA(target,CRED_TYPE_GENERIC,0)||GetLastError()==ERROR_NOT_FOUND?0:1;
 if(!strcmp(argv[1],"put")){BYTE bytes[CRED_MAX_CREDENTIAL_BLOB_SIZE+1];size_t n=fread(bytes,1,sizeof(bytes),stdin);if(!n||n>CRED_MAX_CREDENTIAL_BLOB_SIZE){SecureZeroMemory(bytes,sizeof(bytes));return 1;}CREDENTIALA c={0};c.Type=CRED_TYPE_GENERIC;c.TargetName=target;c.CredentialBlob=bytes;c.CredentialBlobSize=(DWORD)n;c.Persist=CRED_PERSIST_LOCAL_MACHINE;c.UserName="Hybrid Mail";BOOL ok=CredWriteA(&c,0);SecureZeroMemory(bytes,sizeof(bytes));return ok?0:1;}
 return 1;
}
