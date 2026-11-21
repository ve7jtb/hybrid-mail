use std::{io::{self,Read,BufRead,Write},fs,env,path::Path};
use yubikit::{piv::{PivSession,PivError,PivPin,ManagementKey,Slot,KeyType,PinPolicy,TouchPolicy},platform::pcsc::{list_readers,PcscSmartCardConnection}};
use zeroize::Zeroizing;
use base64::{Engine,engine::general_purpose::STANDARD};
type Result<T> = std::result::Result<T,String>;
fn absent<T>(result:std::result::Result<T,PivError>,sw:u16)->Result<bool>{
 match result {Ok(_)=>Ok(false),Err(PivError::Connection(e)) if e.sw()==Some(sw)=>Ok(true),Err(_)=>Err("Cannot establish empty slot state; refusing provisioning".into())}
}
fn touch_policy(slot:Slot)->TouchPolicy {
 match slot {Slot::Signature|Slot::KeyManagement|Slot::Retired3|Slot::Retired5=>TouchPolicy::Always,_=>TouchPolicy::Never}
}
fn key_touch_policy(slot:Slot,_algorithm:KeyType)->TouchPolicy {
 // Slots 88/89 perform standalone classical operations for both Level 3 and Level 5.
 if slot==Slot::Retired3 && _algorithm==KeyType::Ed25519 {return TouchPolicy::Never;}
 if matches!(slot,Slot::Retired7|Slot::Retired8) {TouchPolicy::Always}else{touch_policy(slot)}
}

trait Card {
 fn empty(&mut self,slot:Slot)->Result<bool>;
 fn generate(&mut self,slot:Slot,alg:KeyType)->Result<Vec<u8>>;
 fn verify(&mut self,slot:Slot,alg:KeyType,expected:&[u8])->Result<bool>;
}
impl Card for PivSession<PcscSmartCardConnection>{
 fn empty(&mut self,slot:Slot)->Result<bool>{
  let key=absent(self.get_slot_metadata(slot),0x6a88)?;
  let cert=absent(self.get_certificate(slot),0x6a82)?;
  Ok(key&&cert)
 }
 fn verify(&mut self,slot:Slot,alg:KeyType,expected:&[u8])->Result<bool>{
  let m=self.get_slot_metadata(slot).map_err(|_|"Cannot read saved key metadata")?;
  Ok(m.generated&&m.key_type==alg&&m.pin_policy==PinPolicy::Always&&m.touch_policy==key_touch_policy(slot,alg)&&m.public_key.to_spki().map_err(|_|"Cannot encode saved key")?==expected)
 }
 fn generate(&mut self,slot:Slot,alg:KeyType)->Result<Vec<u8>>{
  let key=self.generate_key(slot,alg,PinPolicy::Always,key_touch_policy(slot,alg)).map_err(|_|"On-device key generation failed; no retry. Some slots may now be provisioned")?;
  let metadata=self.get_slot_metadata(slot).map_err(|_|"Cannot verify generated key")?;
  if metadata.key_type!=alg||!metadata.generated||metadata.pin_policy!=PinPolicy::Always||metadata.touch_policy!=key_touch_policy(slot,alg){return Err("Generated key metadata does not match".into());}
  let der=key.to_spki().map_err(|_|"Cannot encode public key")?;
  if der!=metadata.public_key.to_spki().map_err(|_|"Cannot encode key metadata")?{return Err("Generated public key mismatch".into());}
  Ok(der)
 }
}
fn generate_certification(card:&mut impl Card)->Result<Vec<(String,Vec<u8>)>> {
 let plan=[(Slot::Retired5,KeyType::MlDsa65),(Slot::Retired6,KeyType::Ed25519),(Slot::Retired7,KeyType::Ed25519),(Slot::Retired8,KeyType::X25519)];
 for (slot,_) in plan {if !card.empty(slot)?{return Err("Migration slots 86-89 contain a key or certificate; generation refused".into());}}
 let mut out=Vec::new();for (slot,alg) in plan{if !card.empty(slot)?{return Err("Target slot became occupied; inspect partial generation".into());}out.push((format!("{:02x}",slot as u8),card.generate(slot,alg)?));}Ok(out)
}
fn require_empty(card:&mut impl Card)->Result<()> {
 for slot in Slot::key_slots(){if !card.empty(slot)?{return Err(format!("YubiKey is not empty: PIV slot {:02x} is provisioned. No keys were changed.",slot as u8));}}
 Ok(())
}
fn plan(profile:&str)->Result<Vec<(Slot,KeyType)>> {
 let (ml,kem,ec)=match profile {
  "level2"=>(KeyType::MlDsa44,KeyType::MlKem768,KeyType::EccP256),
  "level3"|"level3-openpgp"=>(KeyType::MlDsa65,KeyType::MlKem768,KeyType::EccP384),
  "level5"|"pure"|"hybrid"=>(KeyType::MlDsa87,KeyType::MlKem1024,KeyType::EccP384),
  _=>return Err("Unknown provisioning profile".into())
 };
 let mut p=vec![(Slot::Signature,ml),(Slot::KeyManagement,kem),(Slot::Retired2,ec),(Slot::Retired1,ec)];
 if profile=="level5"{p.extend([(Slot::Retired3,KeyType::MlKem768),(Slot::Retired4,KeyType::X25519),(Slot::Retired7,KeyType::EccP384),(Slot::Retired8,KeyType::EccP384)]);}
 if profile=="level3-openpgp"{p.extend([(Slot::Retired3,KeyType::Ed25519),(Slot::Retired4,KeyType::X25519),(Slot::Retired5,KeyType::MlDsa65),(Slot::Retired6,KeyType::Ed25519),(Slot::Retired7,KeyType::Ed25519),(Slot::Retired8,KeyType::X25519)]);}
 Ok(p)
}
fn generate(card:&mut impl Card,profile:&str,mut save:impl FnMut(Slot,Vec<u8>)->Result<()>)->Result<()> {
 require_empty(card)?;
 for (slot,alg) in plan(profile)? {if !card.empty(slot)?{return Err("Target slot is no longer empty; stopped without overwriting it".into());}save(slot,card.generate(slot,alg)?)?;}
 Ok(())
}
fn validate_resume(card:&mut impl Card,profile:&str,saved:&std::collections::HashMap<u8,Vec<u8>>)->Result<()> {
 let p=plan(profile)?;
 for slot in Slot::key_slots(){
  if let Some((_,alg))=p.iter().find(|(s,_)|*s==slot){
   if let Some(der)=saved.get(&(slot as u8)){if !card.verify(slot,*alg,der)?{return Err("Saved public key or policy differs; recovery stopped without changing keys".into());}}
   else if !card.empty(slot)?{return Err(format!("Slot {:02x} is occupied but has no recorded public key; inspect the interrupted generation. No keys changed.",slot as u8));}
  }else if !card.empty(slot)?{return Err("Unexpected occupied slot outside this setup; no keys changed".into());}
 }
 Ok(())
}
fn resume_generation(card:&mut impl Card,profile:&str,saved:&std::collections::HashMap<u8,Vec<u8>>,mut save:impl FnMut(Slot,Vec<u8>)->Result<()>)->Result<()> {
 validate_resume(card,profile,saved)?;
 for (slot,alg) in plan(profile)?{if !saved.contains_key(&(slot as u8)) {if !card.empty(slot)?{return Err("Recovery target became occupied; no overwrite".into());}save(slot,card.generate(slot,alg)?)?;}}
 Ok(())
}
fn save_public(folder:&Path,slot:Slot,der:&[u8])->Result<()> {
 let path=folder.join(format!("{:02x}-public.der",slot as u8));
 let mut f=fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|_|"Cannot create public-key journal entry; stopped")?;
 f.write_all(der).and_then(|_|f.sync_all()).map_err(|_|"Cannot save public key; inspect partial provisioning".into())
}
// Read the actual beta version before opening PIV, as ykman does. The
// override only applies to the development placeholder, and is reset per reader.
fn open_piv(conn:PcscSmartCardConnection)->Result<PivSession<PcscSmartCardConnection>> {
 use yubikit::{core::{set_override_version,Version},management::ManagementSession};
 set_override_version(Version(0,0,1));
 let mut management=ManagementSession::new(conn).map_err(|(e,_)|format!("Cannot initialize YubiKey management: {e}"))?;
 let info=management.read_device_info().map_err(|e|format!("Cannot read YubiKey firmware information: {e}"))?;
 set_override_version(info.version_qualifier.version);
 let result=PivSession::new(management.into_connection()).map_err(|(e,_)|format!("Cannot initialize YubiKey PIV: {e}"));
 set_override_version(Version(0,0,1));
 result
}
fn main_inner()->Result<()> {
 let args:Vec<String>=env::args().collect();
 if args.len()==2&&args[1]=="detect" {
  let mut found=None;
  for reader in list_readers().map_err(|_|"Cannot enumerate smart card readers")? {
   let conn=PcscSmartCardConnection::new(&reader,true).map_err(|_|"Cannot access an inserted smart card; close other token applications and insert only the intended YubiKey")?;
   let mut piv=open_piv(conn)?;
   let serial=piv.get_serial().map_err(|e|format!("Cannot read YubiKey PIV serial: {e}"))?;
   if found.is_some(){return Err("Multiple YubiKeys detected; insert only the key to provision".into());}
   found=Some((serial,piv));
  }
  let (serial,mut card)=found.ok_or("No accessible YubiKey detected; insert the key to provision")?;
  if card.version().0<6{return Err("PQC YubiKey firmware 6 or later is required".into());}
  require_empty(&mut card)?;
  println!("{serial}");return Ok(());
 }
 if args.len()!=3&&args.len()!=5{return Err("Expected check SERIAL or create SERIAL pure|hybrid OUTPUT".into());}
 let object=args[1]=="objects";let resume=args[1]=="resume";let create=args[1]=="create"||resume;let read=args[1]=="read";if !object&&!create&&!read&&args[1]!="check"{return Err("Invalid operation".into());}
 let serial:u32=args[2].parse().map_err(|_|"Invalid device serial")?;
 let mut found=None;
 for reader in list_readers().map_err(|_|"Cannot enumerate smart card readers")? {
  let Ok(conn)=PcscSmartCardConnection::new(&reader,true) else {continue};
  let mut piv=open_piv(conn)?;
  if serial==0||piv.get_serial().ok()==Some(serial){if found.is_some(){return Err("Insert only one YubiKey".into());}found=Some(piv);if serial!=0{break;}}
 }
 let mut card=found.ok_or("Required YubiKey not found or busy; connect the specified serial and close other token applications")?;
 if card.version().0<6{return Err("PQC YubiKey firmware 6 or later is required".into());}
 if object {return objects(&mut card);}
 if read {
  if args.len()!=5||!["pure","hybrid","level2","level3","level3-openpgp","level5"].contains(&args[3].as_str()){return Err("Invalid read profile".into());}
  let mut slots=vec![Slot::Signature,Slot::KeyManagement];if args[3]!="pure"{slots.extend([if Path::new(&args[4]).join("83-public.der").exists(){Slot::Retired2}else{Slot::Authentication},Slot::Retired1]);}
  if args[3]=="level5"{slots.extend([Slot::Retired3,Slot::Retired4,Slot::Retired7,Slot::Retired8]);}
  if args[3]=="level3-openpgp"{slots=plan(&args[3])?.iter().map(|(s,_)|*s).collect();}
  let mut public=serde_json::Map::new();
  for slot in slots{let m=card.get_slot_metadata(slot).map_err(|_|"Cannot read pending key metadata")?;let der=m.public_key.to_spki().map_err(|_|"Cannot encode public key")?;
   let name=format!("{:02x}",slot as u8);let expected=fs::read(Path::new(&args[4]).join(format!("{name}-public.der"))).map_err(|_|"Missing saved public key")?;
   if der!=expected||!m.generated{return Err("Pending setup does not match this YubiKey's generated keys".into());}
   if Path::new(&args[4]).join("provisioning.json").exists(){let alg=plan(&args[3])?.into_iter().find(|(s,_)|*s==slot).ok_or("Unexpected setup slot")?.1;if !card.verify(slot,alg,&der)?{return Err("Pending key algorithm or policy differs".into());}}public.insert(name,serde_json::Value::String(STANDARD.encode(der)));
  }println!("{}",serde_json::Value::Object(public));return Ok(());
 }
 if !create {require_empty(&mut card)?;println!("EMPTY");return Ok(());}
 if args.len()!=5 {return Err("Invalid creation profile".into());}let _=plan(&args[3])?;
 let folder=Path::new(&args[4]);let journal=serde_json::json!({"version":1,"serial":serial,"profile":args[3]});
 let mut saved=std::collections::HashMap::new();
 if resume {
  let data=fs::read(folder.join("provisioning.json")).map_err(|_|"Missing initial provisioning journal; no key generation permitted")?;
  if serde_json::from_slice::<serde_json::Value>(&data).map_err(|_|"Invalid provisioning journal")?!=journal{return Err("Provisioning journal serial/profile mismatch".into());}
  for (slot,_) in plan(&args[3])?{let path=folder.join(format!("{:02x}-public.der",slot as u8));if path.exists(){saved.insert(slot as u8,fs::read(path).map_err(|_|"Cannot read saved public key")?);}}
  validate_resume(&mut card,&args[3],&saved)?;
 }else{
  require_empty(&mut card)?;fs::create_dir(folder).map_err(|_|"Choose a new public setup directory")?;
  let mut f=fs::OpenOptions::new().write(true).create_new(true).open(folder.join("provisioning.json")).map_err(|_|"Cannot create setup journal")?;
  f.write_all(journal.to_string().as_bytes()).and_then(|_|f.sync_all()).map_err(|_|"Cannot persist setup journal")?;
 }
 // Read provisioning credentials only after the empty check, never from args/env.
 let mut input=Zeroizing::new(String::new());io::stdin().take(2049).read_to_string(&mut input).map_err(|_|"Cannot read credentials")?;
 if input.len()>2048{return Err("Credential input too large".into());}
 let mut lines=input.lines();let pin=PivPin::new(lines.next().ok_or("Missing PIN")?).map_err(|_|"Invalid PIN format")?;
 let hex=lines.next().ok_or("Missing management key")?;
 if ![32,48,64].contains(&hex.len()){return Err("Management key must contain 32, 48 or 64 hex characters".into());}
 let mut raw=Zeroizing::new(Vec::new());for pair in hex.as_bytes().chunks(2){raw.push(u8::from_str_radix(std::str::from_utf8(pair).map_err(|_|"Invalid management key")?,16).map_err(|_|"Invalid management key")?);}
 let meta=card.get_management_key_metadata().map_err(|_|"Cannot inspect management key algorithm")?;
 let key=ManagementKey::new(meta.key_type,&raw).map_err(|_|"Management key length does not match device algorithm")?;
 card.authenticate(&key).map_err(|_|"Management-key authentication failed; no retry")?;
 card.verify_pin(&pin).map_err(|_|"PIN verification failed; no retry")?;
 let mut public=serde_json::Map::new();for (slot,der) in &saved {public.insert(format!("{slot:02x}"),serde_json::Value::String(STANDARD.encode(der)));}
 let mut save=|slot:Slot,der:Vec<u8>|{save_public(folder,slot,&der)?;public.insert(format!("{:02x}",slot as u8),serde_json::Value::String(STANDARD.encode(der)));Ok(())};
 if resume{resume_generation(&mut card,&args[3],&saved,&mut save)?;}else{generate(&mut card,&args[3],&mut save)?;}

 println!("{}",serde_json::Value::Object(public));Ok(())
}

// Bounded JSON lines over pipes; credentials are never command-line arguments.
fn objects(card:&mut PivSession<PcscSmartCardConnection>)->Result<()> {
 let stdin=io::stdin();let mut input=stdin.lock();
 loop {
  let mut line=Zeroizing::new(String::new());let n=(&mut input).take(16385).read_line(&mut line).map_err(|_|"Cannot read card request")?;
  if n==0{return Ok(());}if n>16384||!line.ends_with('\n'){return Err("Card request too large".into());}
  let response=(||->Result<serde_json::Value>{
   let mut v:serde_json::Value=serde_json::from_str(&line).map_err(|_|"Invalid card request")?;
   let op=v["op"].as_str().ok_or("Missing operation")?.to_owned();
   if op=="serial"{return Ok(serde_json::json!(card.get_serial().map_err(|_|"Cannot read serial")?));}
   if op=="key"{let value=u8::from_str_radix(v["slot"].as_str().ok_or("Missing slot")?,16).map_err(|_|"Invalid slot")?;
    let slot=Slot::key_slots().find(|s|*s as u8==value).ok_or("Invalid key slot")?;
    let meta=match card.get_slot_metadata(slot){Ok(m)=>m,Err(PivError::Connection(e)) if e.sw()==Some(0x6a88)=>return Ok(serde_json::Value::Null),Err(_)=>return Err("Cannot read slot metadata".into())};
    return Ok(serde_json::json!(STANDARD.encode(meta.public_key.to_spki().map_err(|_|"Cannot encode public key")?)));}
   if op=="auth"{let secret=v["management"].take();let hex=Zeroizing::new(match secret{serde_json::Value::String(s)=>s,_=>return Err("Missing management key".into())});
    if ![32,48,64].contains(&hex.len()){return Err("Invalid management key length".into());}
    let mut raw=Zeroizing::new(Vec::new());for pair in hex.as_bytes().chunks(2){raw.push(u8::from_str_radix(std::str::from_utf8(pair).map_err(|_|"Invalid management key")?,16).map_err(|_|"Invalid management key")?);}
    let meta=card.get_management_key_metadata().map_err(|_|"Cannot read management key metadata")?;
    card.authenticate(&ManagementKey::new(meta.key_type,&raw).map_err(|_|"Management key length mismatch")?).map_err(|_|"Management authentication failed; no retry")?;return Ok(serde_json::Value::Null);}
   if op=="certification-empty"{
    if !card.empty(Slot::Retired5)?||!card.empty(Slot::Retired6)?||!card.empty(Slot::Retired7)?||!card.empty(Slot::Retired8)?{return Err("Migration slots 86-89 contain a key or certificate; generation refused".into());}
    return Ok(serde_json::Value::Null);}
   if op=="certification-generate"{
    if !card.empty(Slot::Retired5)?||!card.empty(Slot::Retired6)?||!card.empty(Slot::Retired7)?||!card.empty(Slot::Retired8)?{return Err("Migration slots 86-89 must both be empty; no keys changed".into());}
    let generated=generate_certification(card)?;let mut out=serde_json::Map::new();for (slot,der) in generated{out.insert(slot,serde_json::json!(STANDARD.encode(der)));}return Ok(serde_json::Value::Object(out));}
   if op=="move"{
    if !card.empty(Slot::Retired2)?{return Err("Slot 83 key or certificate is occupied; migration refused".into());}
    let before=card.get_slot_metadata(Slot::Authentication).map_err(|_|"Missing 9a key")?;
    if ![KeyType::EccP256,KeyType::EccP384].contains(&before.key_type){return Err("Migration supports only ECDSA P-256/P-384".into());}
    let cert=match card.get_certificate(Slot::Authentication){Ok(c)=>Some(c),Err(PivError::Connection(e)) if e.sw()==Some(0x6a82)=>None,Err(_)=>return Err("Cannot inspect 9a certificate".into())};
    card.move_key(Slot::Authentication,Slot::Retired2).map_err(|_|"Move failed or outcome unknown; inspect slots before retrying")?;
    let after=card.get_slot_metadata(Slot::Retired2).map_err(|_|"Key moved; cannot verify destination")?;
    if before.public_key.to_spki().ok()!=after.public_key.to_spki().ok()||before.pin_policy!=after.pin_policy||before.touch_policy!=after.touch_policy{return Err("Key moved; destination verification failed".into());}
    if let Some(c)=cert{card.put_certificate(Slot::Retired2,&c,false).map_err(|_|"Key moved; certificate copy failed; recover mapping to 83")?;if card.get_certificate(Slot::Retired2).ok().as_ref()!=Some(&c){return Err("Key moved; certificate copy verification failed".into());}card.delete_certificate(Slot::Authentication).map_err(|_|"Key moved; old 9a certificate remains")?;}
    return Ok(serde_json::Value::Null);
   }
   let tag=v["tag"].as_u64().ok_or("Missing object tag")? as u32;
   if !object_allowed(&op,tag){return Err("Object outside PQ Mail namespace".into());}
   if op=="get"{return match card.get_object_raw(tag){Ok(b)=>Ok(serde_json::json!(STANDARD.encode(b))),Err(PivError::Connection(e)) if e.sw()==Some(0x6a82)=>Ok(serde_json::Value::Null),Err(_)=>Err("PIV object read failed".into())};}
   if op=="delete"{card.put_object_raw(tag,None).map_err(|_|"PQ Mail bundle object deletion failed; inspect local recovery backup before retrying")?;return Ok(serde_json::Value::Null);}
   if op=="put"{let data=STANDARD.decode(v["data"].as_str().ok_or("Missing object data")?).map_err(|_|"Invalid object bytes")?;if data.len()>2068{return Err("Object too large".into());}card.put_object_raw(tag,Some(&data)).map_err(|_|"PIV object write failed (possibly insufficient storage). Previous bank retained; do not retry blindly")?;return Ok(serde_json::Value::Null);}
   Err("Invalid card operation".into())
  })();
  let reply=match response {Ok(value)=>serde_json::json!({"value":value}),Err(e)=>serde_json::json!({"error":e})};println!("{reply}");io::stdout().flush().map_err(|_|"Cannot write card response")?;
 }
}

fn main(){if let Err(error)=main_inner(){eprintln!("{error}");std::process::exit(1);}}
#[cfg(test)] mod tests {
 use super::*;use std::collections::HashSet;
 struct Fake{occupied:HashSet<u8>,generated:Vec<u8>,fail:bool,algorithms:Vec<KeyType>}
 impl Card for Fake{fn verify(&mut self,s:Slot,_a:KeyType,d:&[u8])->Result<bool>{Ok(self.occupied.contains(&(s as u8))&&d==[1])}fn empty(&mut self,s:Slot)->Result<bool>{if self.fail{Err("unknown".into())}else{Ok(!self.occupied.contains(&(s as u8)))}}fn generate(&mut self,s:Slot,alg:KeyType)->Result<Vec<u8>>{self.generated.push(s as u8); self.algorithms.push(alg);self.occupied.insert(s as u8);Ok(vec![1])}}
 #[test]fn presence_policy(){assert_eq!(touch_policy(Slot::Signature),TouchPolicy::Always);assert_eq!(touch_policy(Slot::KeyManagement),TouchPolicy::Always);assert_eq!(touch_policy(Slot::Retired1),TouchPolicy::Never);assert_eq!(touch_policy(Slot::Retired2),TouchPolicy::Never);assert_eq!(touch_policy(Slot::Retired5),TouchPolicy::Always);for slot in [Slot::Retired6,Slot::Retired7,Slot::Retired8]{assert_eq!(touch_policy(slot),TouchPolicy::Never);}}
 #[test]fn standalone_classical_presence(){
  for slot in [Slot::Retired7,Slot::Retired8]{assert_eq!(key_touch_policy(slot,KeyType::EccP384),TouchPolicy::Always);}
  assert_eq!(key_touch_policy(Slot::Retired7,KeyType::Ed25519),TouchPolicy::Always);
  assert_eq!(key_touch_policy(Slot::Retired8,KeyType::X25519),TouchPolicy::Always);
  for slot in [Slot::Retired1,Slot::Retired2]{assert_eq!(key_touch_policy(slot,KeyType::EccP384),TouchPolicy::Never);}
  assert_eq!(key_touch_policy(Slot::Retired4,KeyType::X25519),TouchPolicy::Never);
 }
 #[test]fn migration_preserves_existing_and_checks_all_targets(){for occupied in [0x86,0x87,0x88,0x89]{let mut f=Fake{occupied:HashSet::from([0x9c,0x9d,0x84,0x85,occupied]),generated:vec![],algorithms:vec![],fail:false};assert!(generate_certification(&mut f).is_err());assert!(f.generated.is_empty());}let mut f=Fake{occupied:HashSet::from([0x9c,0x9d,0x84,0x85]),generated:vec![],algorithms:vec![],fail:false};generate_certification(&mut f).unwrap();assert_eq!(f.generated,vec![0x86,0x87,0x88,0x89]);assert!(generate_certification(&mut f).is_err());}
 #[test]fn refuses_every_occupied_slot(){for s in Slot::key_slots(){let mut f=Fake{occupied:HashSet::from([s as u8]),generated:vec![],algorithms:vec![],fail:false};assert!(generate(&mut f,"level5",|_,_|Ok(())).is_err());assert!(f.generated.is_empty());}}
 #[test]fn unknown_is_not_empty(){let mut f=Fake{occupied:HashSet::new(),generated:vec![],algorithms:vec![],fail:true};assert!(generate(&mut f,"level5",|_,_|Ok(())).is_err());assert!(f.generated.is_empty());}
 #[test]fn profiles_and_no_rerun(){for profile in ["pure","hybrid","level2","level3","level3-openpgp","level5"]{let mut f=Fake{occupied:HashSet::new(),generated:vec![],algorithms:vec![],fail:false};generate(&mut f,profile,|_,_|Ok(())).unwrap();assert_eq!(f.generated,if profile=="level5"{vec![0x9c,0x9d,0x83,0x82,0x84,0x85,0x88,0x89]}else if profile=="level3-openpgp"{vec![0x9c,0x9d,0x83,0x82,0x84,0x85,0x86,0x87,0x88,0x89]}else{vec![0x9c,0x9d,0x83,0x82]});
 let expected=match profile{"level2"=>vec![KeyType::MlDsa44,KeyType::MlKem768,KeyType::EccP256,KeyType::EccP256],"level3"|"level3-openpgp"=>vec![KeyType::MlDsa65,KeyType::MlKem768,KeyType::EccP384,KeyType::EccP384],_=>vec![KeyType::MlDsa87,KeyType::MlKem1024,KeyType::EccP384,KeyType::EccP384]};let mut expected=expected;if profile=="level5"{expected.extend([KeyType::MlKem768,KeyType::X25519,KeyType::EccP384,KeyType::EccP384]);}if profile=="level3-openpgp"{expected.extend([KeyType::Ed25519,KeyType::X25519,KeyType::MlDsa65,KeyType::Ed25519,KeyType::Ed25519,KeyType::X25519]);}assert_eq!(f.algorithms,expected);assert!(generate(&mut f,profile,|_,_|Ok(())).is_err());}}
 #[test]fn partial_failure_never_retries(){let mut f=Fake{occupied:HashSet::new(),generated:vec![],algorithms:vec![],fail:false};assert!(generate(&mut f,"level5",|_,_|Err("disk failure".into())).is_err());assert_eq!(f.generated.len(),1);assert!(generate(&mut f,"level5",|_,_|Ok(())).is_err());assert_eq!(f.generated.len(),1);}
 #[test]fn level3_complete_plan_and_resume(){
  let mut f=Fake{occupied:HashSet::new(),generated:vec![],algorithms:vec![],fail:false};let mut saved=std::collections::HashMap::new();
  assert!(generate(&mut f,"level3-openpgp",|s,d|{saved.insert(s as u8,d);if saved.len()==4{Err("interrupted".into())}else{Ok(())}}).is_err());
  assert_eq!(f.generated,vec![0x9c,0x9d,0x83,0x82]);
  let mut complete=saved.clone();resume_generation(&mut f,"level3-openpgp",&saved,|s,d|{complete.insert(s as u8,d);Ok(())}).unwrap();
  resume_generation(&mut f,"level3-openpgp",&complete,|_,_|panic!("Complete setup generated a key")).unwrap();
  assert_eq!(f.generated,vec![0x9c,0x9d,0x83,0x82,0x84,0x85,0x86,0x87,0x88,0x89]);
  assert_eq!(plan("level3-openpgp").unwrap().len(),10);
  assert_eq!(key_touch_policy(Slot::Retired3,KeyType::Ed25519),TouchPolicy::Never);
  assert_eq!(key_touch_policy(Slot::Retired3,KeyType::MlKem768),TouchPolicy::Always);
 }
 #[test]fn recovery_rejects_unrecorded_keys_and_mismatch_before_generation(){
  for (slot,der) in [(0x84,vec![]),(0x9c,vec![2]),(0x90,vec![])] {
   let mut f=Fake{occupied:HashSet::from([slot]),generated:vec![],algorithms:vec![],fail:false};let mut saved=std::collections::HashMap::new();
   if !der.is_empty(){saved.insert(slot,der);}
   assert!(resume_generation(&mut f,"level3-openpgp",&saved,|_,_|Ok(())).is_err());assert!(f.generated.is_empty());
  }
 }

}

// Public certificate snapshots are read-only; PUT remains restricted to bundle banks.
fn object_allowed(op:&str,tag:u32)->bool {
 (0x5f5000..=0x5f5020).contains(&tag)||(0x5f5100..=0x5f5120).contains(&tag)||(0x5f5200..=0x5f5220).contains(&tag)||
 (op=="get"&&([0x5fc105,0x5fc10a,0x5fc10b,0x5fc101].contains(&tag)||(0x5fc10d..=0x5fc120).contains(&tag)))
}
#[test]
fn certificate_snapshots_are_read_only(){
 for tag in [0x5fc105,0x5fc10a,0x5fc10b,0x5fc101,0x5fc10d,0x5fc110,0x5fc120]{assert!(object_allowed("get",tag));assert!(!object_allowed("put",tag));}
 assert!(!object_allowed("get",0x5fc109));assert!(object_allowed("put",0x5f5000));
 assert!(object_allowed("delete",0x5f5000));assert!(object_allowed("delete",0x5f5100));
 for tag in [0x5fc105,0x5fc10a,0x5fc10b,0x5fc101,0x5fc10d,0x5fc120,0x5fc109]{assert!(!object_allowed("delete",tag));}
}

#[test]
fn companion_namespace_is_bounded(){for tag in 0x5f5200..=0x5f5220{assert!(object_allowed("get",tag));assert!(object_allowed("put",tag));}assert!(!object_allowed("put",0x5f5221));assert!(!object_allowed("put",0x5f51ff));}
