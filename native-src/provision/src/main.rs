use std::{io::{self,Read},fs,env,path::Path};
use yubikit::{piv::{PivSession,PivError,PivPin,ManagementKey,Slot,KeyType,PinPolicy,TouchPolicy},platform::pcsc::{list_readers,PcscSmartCardConnection}};
use zeroize::Zeroizing;
use base64::{Engine,engine::general_purpose::STANDARD};
type Result<T> = std::result::Result<T,String>;
fn absent<T>(result:std::result::Result<T,PivError>,sw:u16)->Result<bool>{
 match result {Ok(_)=>Ok(false),Err(PivError::Connection(e)) if e.sw()==Some(sw)=>Ok(true),Err(_)=>Err("Cannot establish empty slot state; refusing provisioning".into())}
}
trait Card {
 fn empty(&mut self,slot:Slot)->Result<bool>;
 fn generate(&mut self,slot:Slot,alg:KeyType)->Result<Vec<u8>>;
}
impl Card for PivSession<PcscSmartCardConnection>{
 fn empty(&mut self,slot:Slot)->Result<bool>{
  let key=absent(self.get_slot_metadata(slot),0x6a88)?;
  let cert=absent(self.get_certificate(slot),0x6a82)?;
  Ok(key&&cert)
 }
 fn generate(&mut self,slot:Slot,alg:KeyType)->Result<Vec<u8>>{
  let key=self.generate_key(slot,alg,PinPolicy::Always,TouchPolicy::Never).map_err(|_|"On-device key generation failed; no retry. Some slots may now be provisioned")?;
  let metadata=self.get_slot_metadata(slot).map_err(|_|"Cannot verify generated key")?;
  if metadata.key_type!=alg||!metadata.generated||metadata.pin_policy!=PinPolicy::Always||metadata.touch_policy!=TouchPolicy::Never{return Err("Generated key metadata does not match".into());}
  let der=key.to_spki().map_err(|_|"Cannot encode public key")?;
  if der!=metadata.public_key.to_spki().map_err(|_|"Cannot encode key metadata")?{return Err("Generated public key mismatch".into());}
  Ok(der)
 }
}
fn require_empty(card:&mut impl Card)->Result<()> {
 for slot in Slot::key_slots(){if !card.empty(slot)?{return Err(format!("YubiKey is not empty: PIV slot {:02x} is provisioned. No keys were changed.",slot as u8));}}
 Ok(())
}
fn generate(card:&mut impl Card,profile:&str,mut save:impl FnMut(Slot,Vec<u8>)->Result<()>)->Result<()> {
 require_empty(card)?;
 let (ml,kem,ec)=match profile {
  "level2"=>(KeyType::MlDsa44,KeyType::MlKem768,KeyType::EccP256),
  "level3"=>(KeyType::MlDsa65,KeyType::MlKem768,KeyType::EccP384),
  "level5"|"pure"|"hybrid"=>(KeyType::MlDsa87,KeyType::MlKem1024,KeyType::EccP384),
  _=>return Err("Unknown provisioning profile".into())
 };
 let plan=[(Slot::Signature,ml),(Slot::KeyManagement,kem),(Slot::Authentication,ec),(Slot::Retired1,ec)];
 for (slot,alg) in plan {if !card.empty(slot)?{return Err("Target slot is no longer empty; stopped without overwriting it".into());}save(slot,card.generate(slot,alg)?)?;}
 Ok(())
}
fn main_inner()->Result<()> {
 let args:Vec<String>=env::args().collect();
 if args.len()==2&&args[1]=="detect" {
  let mut found=None;
  for reader in list_readers().map_err(|_|"Cannot enumerate smart card readers")? {
   let conn=PcscSmartCardConnection::new(&reader,true).map_err(|_|"Cannot access an inserted smart card; close other token applications and insert only the intended YubiKey")?;
   let Ok(mut piv)=PivSession::new(conn) else {continue};
   let Ok(serial)=piv.get_serial() else {continue};
   if found.is_some(){return Err("Multiple YubiKeys detected; insert only the key to provision".into());}
   found=Some((serial,piv));
  }
  let (serial,mut card)=found.ok_or("No accessible YubiKey detected; insert the key to provision")?;
  if card.version().0<6{return Err("PQC YubiKey firmware 6 or later is required".into());}
  require_empty(&mut card)?;
  println!("{serial}");return Ok(());
 }
 if args.len()!=3&&args.len()!=5{return Err("Expected check SERIAL or create SERIAL pure|hybrid OUTPUT".into());}
 let create=args[1]=="create";let read=args[1]=="read";if !create&&!read&&args[1]!="check"{return Err("Invalid operation".into());}
 let serial:u32=args[2].parse().map_err(|_|"Invalid device serial")?;
 let mut found=None;
 for reader in list_readers().map_err(|_|"Cannot enumerate smart card readers")? {
  let Ok(conn)=PcscSmartCardConnection::new(&reader,true) else {continue};
  let Ok(mut piv)=PivSession::new(conn) else {continue};
  if piv.get_serial().ok()==Some(serial){found=Some(piv);break;}
 }
 let mut card=found.ok_or("Required YubiKey not found or busy; connect the specified serial and close other token applications")?;
 if card.version().0<6{return Err("PQC YubiKey firmware 6 or later is required".into());}
 if read {
  if args.len()!=5||!["pure","hybrid","level2","level3","level5"].contains(&args[3].as_str()){return Err("Invalid read profile".into());}
  let mut slots=vec![Slot::Signature,Slot::KeyManagement];if args[3]!="pure"{slots.extend([Slot::Authentication,Slot::Retired1]);}
  let mut public=serde_json::Map::new();
  for slot in slots{let m=card.get_slot_metadata(slot).map_err(|_|"Cannot read pending key metadata")?;let der=m.public_key.to_spki().map_err(|_|"Cannot encode public key")?;
   let name=format!("{:02x}",slot as u8);let expected=fs::read(Path::new(&args[4]).join(format!("{name}-public.der"))).map_err(|_|"Missing saved public key")?;
   if der!=expected||!m.generated{return Err("Pending setup does not match this YubiKey's generated keys".into());}public.insert(name,serde_json::Value::String(STANDARD.encode(der)));
  }println!("{}",serde_json::Value::Object(public));return Ok(());
 }
 require_empty(&mut card)?;
 if !create {println!("EMPTY");return Ok(());}
 if args.len()!=5 || !["pure","hybrid","level2","level3","level5"].contains(&args[3].as_str()){return Err("Invalid creation profile".into());}
 let folder=Path::new(&args[4]);fs::create_dir(folder).map_err(|_|"Choose a new public setup directory")?;
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
 let mut public=serde_json::Map::new();
 generate(&mut card,&args[3],|slot,der|{
  let slot=format!("{:02x}",slot as u8);fs::write(folder.join(format!("{slot}-public.der")),&der).map_err(|_|"Cannot save public key; provisioning stopped")?;
  public.insert(slot,serde_json::Value::String(STANDARD.encode(der)));Ok(())
 })?;
 println!("{}",serde_json::Value::Object(public));Ok(())
}
fn main(){if let Err(error)=main_inner(){eprintln!("{error}");std::process::exit(1);}}
#[cfg(test)] mod tests {
 use super::*;use std::collections::HashSet;
 struct Fake{occupied:HashSet<u8>,generated:Vec<u8>,fail:bool,algorithms:Vec<KeyType>}
 impl Card for Fake{fn empty(&mut self,s:Slot)->Result<bool>{if self.fail{Err("unknown".into())}else{Ok(!self.occupied.contains(&(s as u8)))}}fn generate(&mut self,s:Slot,alg:KeyType)->Result<Vec<u8>>{self.generated.push(s as u8); self.algorithms.push(alg);self.occupied.insert(s as u8);Ok(vec![1])}}
 #[test]fn refuses_every_occupied_slot(){for s in Slot::key_slots(){let mut f=Fake{occupied:HashSet::from([s as u8]),generated:vec![],algorithms:vec![],fail:false};assert!(generate(&mut f,"level5",|_,_|Ok(())).is_err());assert!(f.generated.is_empty());}}
 #[test]fn unknown_is_not_empty(){let mut f=Fake{occupied:HashSet::new(),generated:vec![],algorithms:vec![],fail:true};assert!(generate(&mut f,"level5",|_,_|Ok(())).is_err());assert!(f.generated.is_empty());}
 #[test]fn profiles_and_no_rerun(){for profile in ["pure","hybrid","level2","level3","level5"]{let mut f=Fake{occupied:HashSet::new(),generated:vec![],algorithms:vec![],fail:false};generate(&mut f,profile,|_,_|Ok(())).unwrap();assert_eq!(f.generated,vec![0x9c,0x9d,0x9a,0x82]);
 let expected=match profile{"level2"=>vec![KeyType::MlDsa44,KeyType::MlKem768,KeyType::EccP256,KeyType::EccP256],"level3"=>vec![KeyType::MlDsa65,KeyType::MlKem768,KeyType::EccP384,KeyType::EccP384],_=>vec![KeyType::MlDsa87,KeyType::MlKem1024,KeyType::EccP384,KeyType::EccP384]};assert_eq!(f.algorithms,expected);assert!(generate(&mut f,profile,|_,_|Ok(())).is_err());}}
 #[test]fn partial_failure_never_retries(){let mut f=Fake{occupied:HashSet::new(),generated:vec![],algorithms:vec![],fail:false};assert!(generate(&mut f,"level5",|_,_|Err("disk failure".into())).is_err());assert_eq!(f.generated.len(),1);assert!(generate(&mut f,"level5",|_,_|Ok(())).is_err());assert_eq!(f.generated.len(),1);}
}
