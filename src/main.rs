// ___  ___  ___    ___  _                                _         _   
//| . || . \|_ _|  | |  [_] _ _  ___  ___  _ _  ___  _ _ [_] _ _  _| |_ 
//|   ||  _/ | |   | |- | || ' |/ . |/ ._]| '_]| . \| '_]| || ' |  | |  
//|_|_||_|   |_|   |_|  |_||_|_|\_. |\___.|_|  |  _/|_|  |_||_|_|  |_|  
//                              [___|          |_|                      
//
//  This utility generate fingerprint of APT or hacking group activity, based on MITRE ATT&CK framework
/// imports
use serde_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::fs::File;
use std::env;
use std::io::Write;
use std::path::Path;
use std::io::{self, BufRead};
use sha2::{Sha256, Sha224, Digest};
use md5;
use simhash;
//

// definition of APT structure, that will be used in paring of JSON file
#[derive(Serialize, Deserialize)]
struct APT {
    domain: String,         // operating domain
    name: String,           // title of group
    softwares: Value,       // array of softwares that group uses - see MITRE ATT&CK framework
    techniques: Value,      // array of techniques that group uses - see MITRE ATT&CK framework
}
//

fn main() {
    let args: Vec<String> = env::args().collect();  // collect arguments
    match args[1].as_str(){                         // check arguments
        "-h" | "--help" => help(),                  // invoking help info         
        "-f" =>  match Some(&args[2]){              // JSON parsing 
            Some(_x) => {fingerprint(String::from(&args[2]));},
            _ =>{println!("Please provide a file
                           \n Example: -f example.json");},
        },
        "-r" => read_fingerprints(),                // read fingerprints from APT.fp
        "-s" =>  match Some(&args[2]){              // check similarity between provided fingerprint and entries in APT.fp
            Some(_x) => {similar(String::from(&args[2]));
                        },
            _=>{println!("Please provide a valid fingerprint");
                        },
                }
        _=> println!{"Please provide an argument to this utility.              
        You can use \"-h\" or \"--help\" options for more information on how to use this program"},   // default info without arguments
    };
}


// function that generate fingerprint by provided JSON file
// uses struct APT
// fingerprint result = md5(domain)+sha224(softwares)+sh256(techniques)

fn fingerprint(apt_file:String) {
    ascii_art();
    let data = fs::read_to_string(apt_file)
    .expect("Please, provide a file");
let apt: APT = serde_json::from_str(&data)
    .expect("Unable to parse a json file");
let title = String::from(apt.name.replace(" ",""));
let sofware_fiingerprint = Sha224::new().chain(apt.softwares.to_string())
          .finalize();
let techniques_fingerprint = Sha256::new().chain(apt.techniques.to_string())
            .finalize();
let result = format!("{:x}", (md5::compute(apt.domain.as_bytes()))) 
            + &hex::encode(sofware_fiingerprint) 
            + &hex::encode(techniques_fingerprint);
let result_filename = String::from("APT.fp");
if Path::new(&result_filename).exists(){
    let mut file = fs::OpenOptions::new().append(true)
        .open(result_filename).expect("Cannot open file");
    file.write_all((apt.name + "----" + &result + "\n" ).as_bytes()).expect("Write failed, check your file");
    println!("Your new entry {} added", title);
                                        }
else{
    let mut file = fs::File::create(result_filename).expect("File creation failde");
    file.write_all((apt.name + "----" + &result).as_bytes()).expect("Write failed, check your file");
    println!("Your new entry {} added", title);
    }
}



// function to read file line by line
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = fs::File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

// function to read APT.fp and show it to user
fn read_fingerprints(){
    let content = fs::read_to_string("APT.fp").expect("Unable to read a APT.fp file");
    ascii_art();
    println!("Reading your APT.fp data ...");
    println!{"{}", "-".repeat(64)};
    println!("{}", content);
    }

// function, that show how similar provided fingerprint to entries in APT.fp
// use simhash algorithms to to get similarity score
fn similar(provided_fp:String){
    ascii_art();
    println!("Calculating similarity between provided fingerprint and entries in APT.fp ...");
    match provided_fp.len(){
        152 =>  {println!("Provided fingerprint ---- {}", provided_fp);
                if let Ok(lines) = read_lines("APT.fp"){
                    for line in lines {
                        if let Ok(fp) = line {
                            let fp_split = fp.split("----");
                            let fp_vec = fp_split.collect::<Vec<&str>>();
                            println!{"{}", "-".repeat(64)};
                            println!("{}", fp_vec[0]);
                            println!("{}", simhash::similarity(&fp_vec[1],&provided_fp));
                                            }
                                    }
                        }
                },
        _ => println!("Invalid length, please check your fingerprint, it must be 152 characters long"),
}
}

// ASCII fun
fn ascii_art(){
        println!{"          ____ ___   _____    ____                                                  
        (  _  )  _ \\(_   _)  / ___)_                                   _      ( )_ 
        | (_) | |_) ) | |   | (__ (_) ___    __    __  _ __ _ _   _ __(_) ___ |  _)
        (  _  )  __/  | |   |  __)| |  _  \\/ _  \\/ __ \\  __)  _ \\(  __) |  _  \\ |  
        | | | | |     | |   | |   | | ( ) | (_) |  ___/ |  | (_) ) |  | | ( ) | |_ 
        (_) (_)_)     (_)   (_)   (_)_) (_)\\__  |\\____)_)  |  __/(_)  (_)_) (_)\\__)
                                          ( )_) |          | |                     
                                           \\___/           (_)                     
        "};
    }

// help info to show if none arguments provided

fn help(){
    ascii_art();
    println!{"{}", "-".repeat(64)};
    println!{"This little program parse JSON file with APT.
            \n \"-f\" <file.json> - parse JSON, create fingerprint and add to APT.fp file
            \n      You need to provide a specially crafted JSON file with structure like this:
            \n      \"name\" : chosen title of your APT group
            \n      \"domain\" : structure domain your inspected APT group operate in. MITRE ATT&CK framework describes two domains: enterprise-attack and mobile-attack 
            \n      \"techniques\" : an array of techniques that observed APT group use. Please check MITRE ATT&CK for more information
            \n      \"softwares\" : an array of software that APT group uses. For full list of observed software please consult MITRE ATT&CK
            \n      After you provided a json file, there will be created a file with APT fingerprint or added to file if exists already
            \n  Example: -f example.json
            \n  \"-r\" - read fingerprints from APT.fp (must be in the same folder as this utility binary)
            \n  \"-s\" <fingerprint> - show how similar provided fingerprint to entries in APT.fp file
            \n  Example: -s <your fingerprint>"
        };
    println!{"{}", "-".repeat(64)};
}

