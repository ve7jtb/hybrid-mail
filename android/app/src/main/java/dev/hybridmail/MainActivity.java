package dev.hybridmail;

import android.app.*;
import android.content.*;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import com.yubico.yubikit.android.YubiKitManager;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.piv.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Native Android preview. All cryptography/network work runs off the UI thread. */
public final class MainActivity extends Activity {
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final FreshDeviceGate deviceGate=new FreshDeviceGate();
    private volatile String lastTransport="unknown";
    private YubiKitManager manager;
    private AndroidStore store;
    private LinearLayout page;
    private TextView status;
    private Identity identity;
    private AndroidStore.Entry selected;
    private X509Certificate recipient;
    private byte[] outgoing;
    private final List<MailEngine.Attachment> attachments=new ArrayList<>();
    private boolean encryptDraft;
    private boolean openPgpDraft;
    private OpenPgp.PublicIdentity pgpRecipient,pgpSigner;
    private volatile boolean busy;
    private volatile CompletableFuture<char[]> pendingPin;
    private volatile CompletableFuture<Void> pendingStage;
    private AlertDialog holdingDialog;
    private IoAction documentAction;
    private byte[] exportBytes;
    private String from="",to="",subject="",body="";
    interface Work { void run()throws Exception; }
    interface IoAction { void accept(Uri uri)throws Exception; }
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        Security.removeProvider("BC");Security.insertProviderAt(new BouncyCastleProvider(),1);MailEngine.init();
        try {store=new AndroidStore(this);manager=new YubiKitManager(this);
            manager.startUsbDiscovery(new UsbConfiguration().handlePermissions(true),this::discovered);
            home();if(saved==null)receiveBundle(getIntent());
        }catch(Exception e){error(e);}
    }
    @Override protected void onResume(){super.onResume();if(manager!=null)try{manager.startNfcDiscovery(new NfcConfiguration().skipNdefCheck(true).timeout(15000),this,this::discovered);}catch(Exception ignored){}}
    @Override protected void onPause(){if(manager!=null)manager.stopNfcDiscovery(this);deviceGate.cancel();if(pendingPin!=null)pendingPin.cancel(false);if(pendingStage!=null)pendingStage.cancel(false);super.onPause();}
    @Override protected void onDestroy(){if(manager!=null){manager.stopUsbDiscovery();manager.stopNfcDiscovery(this);}if(pendingPin!=null)pendingPin.cancel(true);worker.shutdownNow();identity=null;super.onDestroy();}
    private void discovered(YubiKeyDevice key){deviceGate.discovered(key);runOnUiThread(()->notice("YubiKey detected over "+key.getTransport()+". Keep it connected during the operation."));}
    private void page(String title){
        var scroll=new ScrollView(this);page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);page.setPadding(32,24,32,32);scroll.addView(page);setContentView(scroll);
        if(android.os.Build.VERSION.SDK_INT>=30)scroll.setOnApplyWindowInsetsListener((v,insets)->{var bars=insets.getInsets(WindowInsets.Type.systemBars());v.setPadding(bars.left,bars.top,bars.right,bars.bottom);return insets;});
        TextView heading=new TextView(this);heading.setText(title);heading.setTextSize(26);page.addView(heading);
        status=new TextView(this);status.setPadding(0,12,0,16);page.addView(status);
        if(!title.equals("PQ Mail"))button("Home",this::home);
    }
    private void text(String s){TextView t=new TextView(this);t.setText(s);t.setTextIsSelectable(true);t.setPadding(0,12,0,12);page.addView(t);}
    private EditText field(LinearLayout p,String hint,String value,boolean secret){EditText e=new EditText(this);e.setHint(hint);e.setText(value);e.setSingleLine(true);if(secret)e.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);p.addView(e);return e;}
    private EditText field(String hint,String value){return field(page,hint,value,false);}
    private void button(String label,Runnable action){Button b=new Button(this);b.setText(label);b.setAllCaps(false);b.setOnClickListener(v->{if(busy){notice("An operation is still running");return;}action.run();});page.addView(b);}
    private void notice(String s){if(status!=null)status.setText(s);}
    private void error(Throwable e){Throwable last=e;while(last.getCause()!=null && !(last instanceof PivDiagnostic))last=last.getCause();String message=last.getMessage();new AlertDialog.Builder(this).setTitle("PQ Mail").setMessage(message==null?last.getClass().getSimpleName():message).setPositiveButton("OK",null).show();}
    private void work(String message,Work action){if(busy)return;busy=true;notice(message);worker.execute(()->{try{action.run();}catch(Exception e){runOnUiThread(()->error(e));}finally{busy=false;runOnUiThread(()->{dismissHolding();notice("Ready — you can remove the YubiKey.");});}});}
    private void home(){page("PQ Mail");text("Android preview • S/MIME with software keys or YubiKey USB/NFC\n"+(identity==null?"Select an identity to begin.":identity.signatureAlgorithm()+"\n"+(selected.serial()==0?"Software identity unlocked":"YubiKey "+selected.serial())));
        button("OpenPGP public identities",this::openPgpKeys);button("Identities & certificates",this::identities);button("Compose signed mail",this::compose);button("Open and verify / decrypt .eml",()->pick(uri->openMessage(read(uri))));button("IMAP inbox & SMTP",this::account);
        button("Lock software identity",()->{identity=null;selected=null;outgoing=null;home();});
    }
    private void identities(){page("Identities & certificates");
        button("Import and trust signing certificate",()->importTrustedCertificate("signing"));
        button("Import and trust encryption certificate",()->importTrustedCertificate("encryption"));
        button("Share certificates…",this::shareCertificates);
        button("Import certificate bundle…",()->pick(uri->reviewBundle(readBundle(uri))));
        button("Create software .p12 — four keys",()->identityForm(false));
        button("Import software .p12",()->pick(uri->{byte[] data=read(uri);runOnUiThread(()->password("Unlock imported .p12",p->importBundle(data,p)));}));
        button("Use existing YubiKey keys — issue certificates",()->identityForm(true));
        button("Import existing YubiKey certificate pair",this::importTokenCertificates);
        try{for(var certificate:store.encryptionContacts())button("Use saved encryption certificate: "+certificate.getSubjectX500Principal()+" • "+certificate.getPublicKey().getAlgorithm(),()->{recipient=certificate;notice("Recipient encryption certificate selected");});}catch(Exception e){error(e);}
        text("YubiKey: existing slots 9c (ML-DSA), 9a (ECDSA), 9d (ML-KEM), 82 (ECDH). This Android preview never generates or replaces token keys. Certificates are saved locally; private keys stay on the YubiKey.");
        try{for(var entry:store.entries())button(entry.toString(),()->select(entry));}catch(Exception e){error(e);}
        if(identity!=null){button("Export signing certificate",()->exportCert(identity.signingCert(),"signing.cer"));button("Export encryption certificate",()->exportCert(identity.encryptionCert(),"encryption.cer"));
            if(selected.serial()==0)button("Export encrypted software .p12",()->export(readPath(store.root.resolve(selected.bundle())),"identity.p12","application/x-pkcs12"));
            else button("Test selected YubiKey identity — no email",()->work("Signing and decrypting test message. Keep YubiKey connected…",this::hardwareTest));
        }
    }
    private void importTokenCertificates(){
        new AlertDialog.Builder(this).setTitle("Import YubiKey certificates").setMessage("First choose the signing certificate, then its encryption certificate (PEM or DER). Connect the matching YubiKey. The app verifies all public keys and remembers its serial; no PIN or private operation is needed.").setNegativeButton("Cancel",null).setPositiveButton("Choose signing certificate",(d,w)->pick(signUri->{
            var factory=java.security.cert.CertificateFactory.getInstance("X.509","BC");
            var sc=(X509Certificate)factory.generateCertificate(new ByteArrayInputStream(read(signUri)));sc.checkValidity();
            runOnUiThread(()->new AlertDialog.Builder(this).setMessage("Now choose the encryption certificate").setPositiveButton("Choose",(a,b)->pick(encUri->{
                var ec=(X509Certificate)factory.generateCertificate(new ByteArrayInputStream(read(encUri)));ec.checkValidity();Identity.validateEncryptionKey(ec.getPublicKey());
                if(sc.getKeyUsage()==null||!sc.getKeyUsage()[0]||ec.getKeyUsage()==null||ec.getKeyUsage().length<3||!ec.getKeyUsage()[2])throw new GeneralSecurityException("Certificate key usage is incorrect");
                var id=new Identity(sc,null,ec,null,null);int serial;
                try(var connection=requireDevice().openConnection(SmartCardConnection.class)){
                    var piv=PivSessions.open(connection);serial=piv.getSerialNumber();
                    for(var e:YubiBackend.keys(id).entrySet())if(!MessageDigest.isEqual(e.getValue().getEncoded(),YubiBackend.publicKey(piv,e.getKey()).getEncoded()))throw new GeneralSecurityException("Certificate does not match YubiKey slot "+e.getKey());
                }
                store.addToken(sc.getSubjectX500Principal()+" • "+id.signatureAlgorithm(),serial,id);runOnUiThread(this::identities);
            })).setNegativeButton("Cancel",null).show());
        })).show();
    }
    private void hardwareTest()throws Exception{
        String email=null;for(var san:identity.signingCert().getSubjectAlternativeNames())if(Integer.valueOf(1).equals(san.get(0))&&Identity.matchesEmail(identity.encryptionCert(),(String)san.get(1))){email=(String)san.get(1);break;}
        if(email==null)throw new GeneralSecurityException("Signing and encryption certificates need a shared email SAN");
        String stage="signing";String signingTransport="unknown";
        try{
        var message=MailEngine.compose(identity,email,email,"PQ Mail Android hardware test","YubiKey signing and decryption verified",identity.encryptionCert(),backend());
        signingTransport=lastTransport;
        signingComplete();stage="decryption";
        var opened=MailEngine.open(message,identity,identity.signingCert(),backend());
        if(!opened.encrypted()||!opened.pinned()||!opened.text().equals("YubiKey signing and decryption verified"))throw new GeneralSecurityException("Round trip failed");
        String report="PASS signing="+signingTransport+" decryption="+lastTransport+"\n"+identity.signatureAlgorithm()+"\n"+identity.encryptionCert().getPublicKey().getAlgorithm()+"\nSignature verified and message decrypted. No email sent; no token keys changed.";
        saveHardwareResult(report);
        runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Test complete — remove your key").setMessage("Signing and decryption are complete. You can remove the YubiKey now.\n\n"+report).setPositiveButton("OK",null).show());
        }catch(Exception e){Throwable cause=e;while(cause.getCause()!=null&&!(cause instanceof PivDiagnostic))cause=cause.getCause();saveHardwareResult("FAIL "+stage+" / "+lastTransport+"\n"+identity.signatureAlgorithm()+"\n"+cause.getClass().getSimpleName()+": "+cause.getMessage());throw e;}
    }
    private void dismissHolding(){if(holdingDialog!=null){holdingDialog.dismiss();holdingDialog=null;}}
    private void signingComplete()throws Exception{
        var result=new CompletableFuture<Void>();pendingStage=result;
        runOnUiThread(()->{
            dismissHolding();
            var dialog=new AlertDialog.Builder(this).setTitle("Signing complete — remove your key")
                .setMessage("The signature is verified. You can remove the NFC key now.\n\nNext is decryption: enter your PIN again, then re-tap only when prompted. This is a separate operation. If using USB, you can leave the key connected.")
                .setPositiveButton("Continue to decryption",(d,w)->result.complete(null))
                .setNegativeButton("Stop test",(d,w)->result.cancel(false)).create();
            dialog.setOnCancelListener(d->result.cancel(false));dialog.show();
            result.whenComplete((v,e)->runOnUiThread(dialog::dismiss));
        });
        try{result.get(180,TimeUnit.SECONDS);}finally{pendingStage=null;if(!result.isDone())result.cancel(false);}
    }
    private void saveHardwareResult(String report)throws IOException{
        String stamped=java.time.Instant.now()+"\n"+report;
        if(!getSharedPreferences("hardware-tests",0).edit().putString("last",stamped).putString("profile."+identity.signatureAlgorithm(),stamped).commit())throw new IOException("Cannot save hardware-test result");
    }
    private void identityForm(boolean token){page(token?"Existing YubiKey identity":"Create software identity");
        EditText email=field("Primary email address",from);EditText extras=field("Up to four additional emails, comma separated","");
        Spinner profile=new Spinner(this);profile.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,TokenProfile.values()));page.addView(profile);
        text("Each profile has pure PQ and hybrid views of the same four keys. Level names refer to the ML-DSA security category; ML-KEM-768 is category 3.");
        button(token?"Read connected key and create certificates":"Create encrypted .p12",()->{
            String mail=email.getText().toString().trim(),extra=extras.getText().toString();TokenProfile p=(TokenProfile)profile.getSelectedItem();
            if(token)work("Read YubiKey, then sign four certificates. Hold NFC key in place.",()->createToken(mail,extra,p));
            else password("New .p12 password (12+ characters)",pass->{
                try{var ids=Identity.generateSoftwareProfile(mail,p,Identity.additionalEmails(mail,extra));String id=UUID.randomUUID().toString();Path path=store.root.resolve(id+".p12");ids.get(1).save(path,pass,ids.get(0));
                    var e=new AndroidStore.Entry(id,mail+" • "+p.code,path.getFileName().toString(),0,"","");store.add(e);identity=ids.get(1);selected=e;from=mail;runOnUiThread(()->{home();export(readPath(path),"identity.p12","application/x-pkcs12");});
                }finally{Arrays.fill(pass,'\0');}
            });
        });
    }
    private byte[] readPath(Path p){try{return Files.readAllBytes(p);}catch(Exception e){throw new IllegalStateException(e);}}
    private void createToken(String email,String extra,TokenProfile profile)throws Exception {
        List<String> sans=Identity.additionalEmails(email,extra);int serial;Map<Slot,PublicKey> keys=new EnumMap<>(Slot.class);
        try(var connection=requireDevice().openConnection(SmartCardConnection.class)){
            var piv=PivSessions.open(connection);serial=piv.getSerialNumber();
            for(Slot slot:List.of(Slot.SIGNATURE,Slot.AUTHENTICATION,Slot.KEY_MANAGEMENT,Slot.RETIRED1))keys.put(slot,YubiBackend.publicKey(piv,slot));
        }
        var backend=new YubiBackend(this::requireDevice,this::requestPin,serial,keys);
        Identity pure=Identity.forTokenProfile(email,profile,keys.get(Slot.SIGNATURE),null,keys.get(Slot.KEY_MANAGEMENT),null,backend,sans);
        Identity hybrid=Identity.forTokenProfile(email,profile,keys.get(Slot.SIGNATURE),keys.get(Slot.AUTHENTICATION),keys.get(Slot.KEY_MANAGEMENT),keys.get(Slot.RETIRED1),backend,sans);
        store.addToken(email+" • "+profile.code+" pure",serial,pure);store.addToken(email+" • "+profile.code+" hybrid",serial,hybrid);
        runOnUiThread(this::identities);
    }
    private YubiKeyDevice requireDevice()throws Exception{
        var result=deviceGate.request();
        if(!result.isDone())runOnUiThread(()->{
            if(result.isDone())return;
            var dialog=new AlertDialog.Builder(this).setTitle("Connect your YubiKey")
                .setMessage("For NFC, move the key away, then tap and hold it against the phone. A fresh tap is required for each signing or decryption operation. Keep it in place until the app says you can remove it. You can also connect over USB.")
                .setNegativeButton("Cancel",(d,w)->deviceGate.cancel()).create();
            dialog.setOnCancelListener(d->deviceGate.cancel());dialog.show();
            result.whenComplete((d,e)->runOnUiThread(dialog::dismiss));
        });
        try{var key=result.get(120,TimeUnit.SECONDS);lastTransport=key.getTransport().toString();
            if(key.getTransport()==com.yubico.yubikit.core.Transport.NFC)runOnUiThread(()->{dismissHolding();holdingDialog=new AlertDialog.Builder(this).setTitle("Hold your YubiKey in place").setMessage("Operation in progress. Keep the key against the phone until the app says you can remove it.").setCancelable(false).create();holdingDialog.show();});
            return key;}
        finally{deviceGate.cancel();}
    }
    private YubiBackend backend(){return new YubiBackend(this::requireDevice,label->requestPin((label.contains("decryption")?identity.encryptionCert().getPublicKey().getAlgorithm():identity.signatureAlgorithm())+" / "+label),selected.serial(),YubiBackend.keys(identity,store.slots(selected)));}
    private char[] requestPin(String algorithm)throws Exception {
        CompletableFuture<char[]> result=new CompletableFuture<>();pendingPin=result;
        runOnUiThread(()->{
            dismissHolding();
            EditText input=new EditText(this);input.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
            input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
            AlertDialog dialog=new AlertDialog.Builder(this).setTitle("YubiKey PIN • "+algorithm).setMessage("You can remove the NFC key now. Enter the PIN with the key away from the phone, then wait for the tap prompt. The app checks the key’s serial and public keys before sending the PIN. It reuses the PIN for this operation’s components, then clears it.").setView(input).setNegativeButton("Cancel",(d,w)->result.cancel(false)).setPositiveButton("Continue",null).create();
            dialog.setOnCancelListener(d->result.cancel(false));dialog.setOnShowListener(d->{input.requestFocus();dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE);dialog.getButton(-1).setOnClickListener(v->{
                char[] pin=new char[input.length()];input.getText().getChars(0,input.length(),pin,0);boolean valid=pin.length>=6&&pin.length<=8;for(char c:pin)valid&=c>=32&&c<=126;
                if(!valid){Arrays.fill(pin,'\0');input.setError("Use a 6–8 character ASCII PIV PIN");return;}
                input.getText().clear();if(!result.complete(pin))Arrays.fill(pin,'\0');dialog.dismiss();
            });});dialog.show();
            result.whenComplete((p,e)->runOnUiThread(()->{input.getText().clear();dialog.dismiss();}));
        });
        try{return result.get(180,TimeUnit.SECONDS);}finally{pendingPin=null;if(!result.isDone())result.cancel(false);}
    }
    interface PasswordAction{void accept(char[] password)throws Exception;}
    private void password(String title,PasswordAction action){EditText input=new EditText(this);input.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        new AlertDialog.Builder(this).setTitle(title).setView(input).setNegativeButton("Cancel",(d,w)->input.getText().clear()).setPositiveButton("Continue",(d,w)->{
            char[] pass=new char[input.length()];input.getText().getChars(0,input.length(),pass,0);input.getText().clear();work("Processing encrypted identity…",()->{try{action.accept(pass);}finally{Arrays.fill(pass,'\0');}});
        }).show();
    }
    private void importBundle(byte[] bytes,char[] pass)throws Exception {
        String id=UUID.randomUUID().toString();Path p=store.root.resolve(id+".p12");Files.write(p,bytes);
        try{List<Identity> loaded=Identity.loadProfiles(p,pass);if(loaded.stream().anyMatch(i->i.signingKey()==null||i.encryptionKey()==null))throw new GeneralSecurityException("Import software bundles with both private keys; use YubiKey identity creation for token keys");
            var e=new AndroidStore.Entry(id,"Imported "+loaded.get(loaded.size()-1).signatureAlgorithm(),p.getFileName().toString(),0,"","");store.add(e);runOnUiThread(()->chooseView(e,loaded));
        }catch(Exception e){Files.deleteIfExists(p);throw e;}
    }
    private byte[] readBundle(Uri uri)throws Exception{
        try(var in=getContentResolver().openInputStream(uri);var out=new ByteArrayOutputStream()){
            if(in==null)throw new IOException("Cannot open certificate bundle");byte[] buffer=new byte[8192];int n;
            while((n=in.read(buffer))!=-1){if(out.size()+n>CertificateBundle.MAX_BYTES)throw new IOException("Bundle exceeds 512 KiB");out.write(buffer,0,n);}return out.toByteArray();
        }
    }
    @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);setIntent(intent);receiveBundle(intent);}
    private void receiveBundle(Intent intent){
        if(intent==null||busy)return;Uri uri=null;
        if(Intent.ACTION_SEND.equals(intent.getAction()))uri=intent.getParcelableExtra(Intent.EXTRA_STREAM);
        else if(Intent.ACTION_VIEW.equals(intent.getAction()))uri=intent.getData();
        if(uri==null)return;if(!"content".equals(uri.getScheme())){error(new IOException("Use the document picker to open this certificate bundle"));return;}
        Uri source=uri;work("Reading shared certificate bundle…",()->reviewBundle(readBundle(source)));
    }
    private void shareCertificates(){work("Preparing public certificate profiles…",()->{
        var entries=store.certificateBundle(selected,identity);byte[] bytes=CertificateBundle.encode(entries);String review=CertificateBundle.review(entries);
        runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Share public certificates?").setMessage(review).setNegativeButton("Cancel",null).setPositiveButton("Share…",(d,w)->{
            try{Files.write(getCacheDir().toPath().resolve("PQ-Mail-certificates.pqcert"),bytes);
                Uri uri=Uri.parse("content://"+getPackageName()+".certificates/PQ-Mail-certificates.pqcert");
                Intent share=new Intent(Intent.ACTION_SEND).setType(CertificateBundle.MIME).putExtra(Intent.EXTRA_STREAM,uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                share.setClipData(ClipData.newRawUri("Public certificate bundle",uri));startActivity(Intent.createChooser(share,"Share certificates — Quick Share"));
            }catch(Exception e){error(e);}
        }).show());
    });}
    private void reviewBundle(byte[] bytes)throws Exception{
        var entries=CertificateBundle.decode(bytes);String review=CertificateBundle.review(entries);
        runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Review public certificate bundle").setMessage(review)
            .setNeutralButton("Cancel",null).setPositiveButton("My YubiKey",(d,w)->work("Importing public identities…",()->{store.importCertificateBundle(entries,true);runOnUiThread(this::identities);}))
            .setNegativeButton("Contact certificates",(d,w)->work("Importing contact certificates…",()->{store.importCertificateBundle(entries,false);runOnUiThread(this::identities);})).show());
    }
    private void importTrustedCertificate(String role){pick(uri->{
        var cert=(X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509","BC").generateCertificate(new ByteArrayInputStream(read(uri)));
        Identity.validateCertificatePurpose(cert,role);String fingerprint=Identity.fingerprint(cert);
        runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Trust "+role+" certificate?")
            .setMessage(cert.getSubjectX500Principal()+"\n"+cert.getPublicKey().getAlgorithm()+"\nSHA-256: "+fingerprint+"\nCompare this fingerprint with the owner. This trusts this exact certificate, not a CA chain.")
            .setNegativeButton("Cancel",null).setPositiveButton("Trust",(d,w)->{try{store.trust(cert,role);if(role.equals("encryption"))recipient=cert;notice("Certificate fingerprint trusted for "+role);}catch(Exception e){error(e);}}).show());
    });}
    private void select(AndroidStore.Entry e){if(e.serial()!=0)work("Loading public certificates…",()->{identity=store.loadToken(e);selected=e;runOnUiThread(this::home);});
        else password("Unlock software .p12",pass->{var ids=Identity.loadProfiles(store.root.resolve(e.bundle()),pass);runOnUiThread(()->chooseView(e,ids));});}
    private void chooseView(AndroidStore.Entry e,List<Identity> ids){String[] labels=ids.stream().map(Identity::signatureAlgorithm).toArray(String[]::new);
        new AlertDialog.Builder(this).setTitle("Outgoing identity profile").setItems(labels,(d,n)->{identity=ids.get(n);selected=e;try{for(var san:identity.signingCert().getSubjectAlternativeNames())if(Integer.valueOf(1).equals(san.get(0))){from=(String)san.get(1);break;}}catch(Exception ignored){}home();}).show();}
    private void openPgpKeys(){
        page("OpenPGP public identities");
        text("Level 3 hybrid draft-05: ML-DSA-65 + P-384 / ML-KEM-768 + P-384. Existing keys are reused; no YubiKey slots change. Public identities are separate from X.509 certificates.");
        if(OpenPgp.supported(identity)){
            button("Create OpenPGP public identity",()->work("Creating three hybrid binding signatures; keep the key connected…",()->{var own=OpenPgp.createOwn(store.root,identity,selected.serial()==0?null:backend());String detail=own.description();runOnUiThread(()->new AlertDialog.Builder(this).setTitle("OpenPGP identity ready").setMessage(detail).setPositiveButton("OK",null).show());}));
            button("Import my existing OpenPGP public identity",()->pick(uri->{var own=OpenPgp.saveOwn(store.root,identity,read(uri));runOnUiThread(()->notice("Own OpenPGP public identity imported."));}));
            button("Export my OpenPGP public key",()->work("Exporting public key…",()->{byte[] data=OpenPgp.loadOwn(store.root,identity).export();runOnUiThread(()->export(data,"PQ-Mail-public.asc","application/pgp-keys"));}));
            button("Use my OpenPGP key as recipient",()->{try{pgpRecipient=OpenPgp.loadOwn(store.root,identity);to=pgpRecipient.email;notice("Own OpenPGP recipient selected.");}catch(Exception e){error(e);}});
        }else text("Select a Level 3 hybrid software or YubiKey identity first.");
        button("Import recipient OpenPGP public key",()->importPgpContact(true));
        button("Import sender OpenPGP public key",()->importPgpContact(false));
        button("Verify with my OpenPGP key",()->{pgpSigner=null;notice("Verification uses your selected OpenPGP identity.");});
        text("Confirm public fingerprints independently. Import verifies self-signatures, not trust. When moving existing keys between devices, import the same OpenPGP public identity to preserve its fingerprints.");
    }
    private void importPgpContact(boolean recipientRole){
        pick(uri->{var key=new OpenPgp.PublicIdentity(read(uri));String description=key.description();runOnUiThread(()->new AlertDialog.Builder(this).setTitle("Use OpenPGP public key?").setMessage(description).setNegativeButton("Cancel",null).setPositiveButton("Use key",(d,w)->{if(recipientRole){pgpRecipient=key;to=key.email;}else pgpSigner=key;notice("OpenPGP public key selected; trust not established.");}).show());});
    }
    private void compose(){if(identity==null){error(new Exception("Select an identity first"));return;}outgoing=null;page("Compose signed mail");text(identity.signatureAlgorithm()+" • "+(selected.serial()==0?"software":"YubiKey "+selected.serial()));
        EditText f=field("From",from),t=field("To",to),s=field("Subject",subject),b=field("Message",body);b.setSingleLine(false);b.setMinLines(5);
        CheckBox format=new CheckBox(this);format.setText("Use OpenPGP (Level 3 hybrid draft; plain text only)");format.setChecked(openPgpDraft);format.setEnabled(OpenPgp.supported(identity));if(!OpenPgp.supported(identity)){openPgpDraft=false;format.setChecked(false);}format.setOnCheckedChangeListener((v,checked)->openPgpDraft=checked);page.addView(format);
        CheckBox encrypt=new CheckBox(this);encrypt.setText("Also encrypt (S/MIME certificate or OpenPGP recipient key)");encrypt.setChecked(encryptDraft);encrypt.setOnCheckedChangeListener((v,checked)->encryptDraft=checked);page.addView(encrypt);
        text(pgpRecipient==null?"No OpenPGP recipient selected; use OpenPGP public identities from Home.":"OpenPGP recipient: "+pgpRecipient.email);
        text(recipient==null?"No recipient certificate loaded":recipient.getSubjectX500Principal()+"\n"+recipient.getPublicKey().getAlgorithm());
        button("Import recipient encryption certificate",()->{from=f.getText().toString();to=t.getText().toString();subject=s.getText().toString();body=b.getText().toString();pick(uri->{byte[] data=read(uri);var cert=(X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509","BC").generateCertificate(new ByteArrayInputStream(data));Identity.validateCertificatePurpose(cert,"encryption");recipient=cert;runOnUiThread(this::compose);});});
        text("Attachments are signed with the body. Enable encryption to protect filenames and contents. Up to 20 files / 10 MiB total.");
        for(var attachment:new ArrayList<>(attachments))button("Remove: "+attachment,()->{attachments.remove(attachment);from=f.getText().toString();to=t.getText().toString();subject=s.getText().toString();body=b.getText().toString();compose();});
        button("Add attachment…",()->{
            from=f.getText().toString();to=t.getText().toString();subject=s.getText().toString();body=b.getText().toString();
            if(attachments.size()>=20){error(new IOException("At most 20 attachments"));return;}
            pick(uri->{String name="attachment.bin";
                try(var cursor=getContentResolver().query(uri,new String[]{android.provider.OpenableColumns.DISPLAY_NAME},null,null,null)){
                    if(cursor!=null&&cursor.moveToFirst())name=cursor.getString(0);
                }
                byte[] bytes=read(uri);long total=bytes.length;for(var item:attachments)total+=item.data().length;
                if(total>MailEngine.MAX_MESSAGE/2)throw new IOException("Attachments exceed 10 MiB");
                var attachment=new MailEngine.Attachment(name,bytes);runOnUiThread(()->{attachments.add(attachment);compose();});
            });
        });
        button("Sign and prepare .eml",()->{from=f.getText().toString().trim();to=t.getText().toString().trim();subject=s.getText().toString();body=b.getText().toString();boolean enc=encrypt.isChecked();if(enc&&!openPgpDraft&&recipient==null){error(new Exception("Import recipient encryption certificate first"));return;}
            if(openPgpDraft&&(!OpenPgp.supported(identity)||!attachments.isEmpty()||(enc&&pgpRecipient==null))){error(new Exception("OpenPGP requires a Level 3 hybrid identity, no attachments, and an OpenPGP recipient key when encrypting."));return;}
            work("Signing "+identity.signatureAlgorithm()+ (enc?" and encrypting…":"…"),()->{outgoing=openPgpDraft?OpenPgp.compose(identity,OpenPgp.loadOwn(store.root,identity),enc?pgpRecipient:null,from,to,subject,body,selected.serial()==0?null:backend()):MailEngine.encode(MailEngine.composeAttachments(identity,from,to,subject,body,enc?recipient:null,selected.serial()==0?null:backend(),List.copyOf(attachments)));runOnUiThread(()->export(outgoing,"message.eml","message/rfc822"));});});
    }
    private void openMessage(byte[] bytes)throws Exception {
        if(OpenPgp.isOpenPgp(bytes)){
            OpenPgp.PublicIdentity own=null;if(OpenPgp.parts(bytes).encrypted()||pgpSigner==null)own=OpenPgp.loadOwn(store.root,identity);
            var opened=OpenPgp.open(bytes,pgpSigner==null?own:pgpSigner,own,identity,selected!=null&&selected.serial()!=0?backend():null);
            runOnUiThread(()->{page("OpenPGP message");text(opened.display());});return;
        }
        var result=MailEngine.open(MailEngine.parse(bytes),identity,null,selected!=null&&selected.serial()!=0?backend():null);
        runOnUiThread(()->{page("S/MIME message");text((result.signerCertificate()==null?"UNSIGNED — sender not verified":"Signature valid • "+result.signatureAlgorithm())+"\n"+(result.encrypted()?"Decrypted":"Unencrypted")+"\nSender address "+(result.fromMatches()?"matches certificate":"DOES NOT match certificate")+"\n"+(store.trusted(result.fingerprint())?"Trusted fingerprint":"Untrusted fingerprint")+"\n"+result.fingerprint());text(result.text());
            for(var attachment:result.attachments())button("Save attachment: "+attachment,()->export(attachment.data(),attachment.name(),"application/octet-stream"));
            if(!result.attachments().isEmpty())text("Saved attachments are decrypted files. Nothing is saved until you choose a destination.");
            if(result.signerCertificate()!=null)button("Trust this signer for encryption",()->{try{var cert=result.signerCertificate();Identity.validateCertificatePurpose(cert,"encryption");
                new AlertDialog.Builder(this).setTitle("Trust encryption certificate?").setMessage("Confirm this fingerprint with the owner before encrypting mail:\n"+result.fingerprint()).setNegativeButton("Cancel",null).setPositiveButton("Trust",(d,w)->{try{store.trust(cert,"encryption");recipient=cert;notice("Encryption certificate trusted and selected");}catch(Exception e){error(e);}}).show();
            }catch(Exception e){error(e);}});
            if(result.signerCertificate()!=null)button("Trust this signer fingerprint",()->new AlertDialog.Builder(this).setTitle("Trust signer?").setMessage("Compare this SHA-256 fingerprint through a trusted channel before accepting:\n"+result.fingerprint()).setNegativeButton("Cancel",null).setPositiveButton("Trust",(d,w)->{try{store.trust(result.signerCertificate());notice("Fingerprint saved as trusted");}catch(Exception e){error(e);}}).show());});
    }
    private void account(){page("IMAP inbox & SMTP");var prefs=getSharedPreferences("mail",0);
        EditText user=field("Account username",prefs.getString("user",from)),imap=field("IMAP TLS host (port 993)",prefs.getString("imap","")),smtp=field("SMTP STARTTLS host (port 587)",prefs.getString("smtp",""));
        EditText pass=field(page,"App password (not saved)","",true);text("TLS is required. Gmail requires an app password where permitted; Google OAuth sign-in is not included in this Android preview.");
        button("Load 10 most recent messages",()->{String u=user.getText().toString(),h=imap.getText().toString(),credential=pass.getText().toString();pass.getText().clear();prefs.edit().putString("user",u).putString("imap",h).putString("smtp",smtp.getText().toString()).apply();
            work("Connecting to IMAP…",()->{try(var inbox=ImapInbox.connect(h,993,u,credential,false)){var entries=inbox.latest();List<byte[]> messages=new ArrayList<>();for(var entry:entries)messages.add(MailEngine.encode(inbox.message(entry.uid())));runOnUiThread(()->{page("Recent inbox");for(int i=0;i<entries.size();i++){int n=i;var e=entries.get(i);button(e.sender()+"\n"+e.subject(),()->work("Verifying message…",()->openMessage(messages.get(n))));}});}});});
        button("Send prepared message via SMTP",()->{if(outgoing==null){error(new Exception("Compose and prepare a message first"));return;}String h=smtp.getText().toString(),u=user.getText().toString();
            new AlertDialog.Builder(this).setTitle("Send email now?").setMessage("Send the prepared signed message to "+to+" through "+h+"?").setNegativeButton("Cancel",null).setPositiveButton("Send",(d,w)->{String credential=pass.getText().toString();pass.getText().clear();work("Sending SMTP…",()->{MailEngine.send(MailEngine.parse(outgoing),h,587,u,credential,false);runOnUiThread(()->new AlertDialog.Builder(this).setMessage("Message sent").setPositiveButton("OK",null).show());});}).show();});
    }
    private void pick(IoAction action){documentAction=action;Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(i,1);}
    private byte[] read(Uri uri)throws Exception {try(var in=getContentResolver().openInputStream(uri);var out=new ByteArrayOutputStream()){if(in==null)throw new IOException("Cannot open file");byte[] block=new byte[8192];int n;while((n=in.read(block))!=-1){if(out.size()+n>MailEngine.MAX_MESSAGE)throw new IOException("File exceeds 20 MiB");out.write(block,0,n);}return out.toByteArray();}}
    private void exportCert(X509Certificate cert,String name){try{export(cert.getEncoded(),name,"application/pkix-cert");}catch(Exception e){error(e);}}
    private void export(byte[] bytes,String name,String mime){exportBytes=bytes;startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(mime).addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,name),2);}
    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(result!=RESULT_OK||data==null){exportBytes=null;documentAction=null;return;}Uri uri=data.getData();if(request==1){IoAction action=documentAction;documentAction=null;work("Opening file…",()->action.accept(uri));}else if(request==2){byte[] bytes=exportBytes;exportBytes=null;work("Saving file…",()->{try(var out=getContentResolver().openOutputStream(uri,"wt")){if(out==null)throw new IOException("Cannot save file");out.write(bytes);}});}}
}
