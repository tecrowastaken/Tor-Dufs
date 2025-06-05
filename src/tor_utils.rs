use crate::args::Args;
use custom_error::custom_error;
use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{self, Child, Command, Stdio};
use std::str::FromStr;
use tempdir::TempDir;
use tor_interface::legacy_tor_client::{LegacyTorClient, LegacyTorClientConfig};
use tor_interface::tor_provider::{TorEvent, TorProvider};

// Copied from the Tests for tor_provider with some modifications


// Screw not being allowed interior mutability 
// I'm making a trait for it so that this isn't bullshit.
trait JustFixTempDirAlready {
    fn safe_close(&mut self) -> std::io::Result<()>;
}

impl JustFixTempDirAlready for TempDir {
    fn safe_close(&mut self) -> std::io::Result<()>{
        std::fs::remove_dir_all(self.path())
    }
}


pub struct TorProcess(Child, TempDir, bool);
impl TorProcess {
    pub fn cleanup_daemon(&mut self){
        if !self.2 {
            let _ = self.0.kill();
            self.1.safe_close().expect("Temporary Directory could not be deleted");
            // clear!
            self.2 = true;
            
        }
    }
}
impl Drop for TorProcess {
    fn drop(&mut self) -> () {
        // incase we abruptly exited...
        self.cleanup_daemon();
    }
}



custom_error! {pub TorControlError
    ControlError{
        buf:String
    } = "Control Error: \"{buf}\""
}

/// In Our case it may not be smart to introduce a
/// second listener so the second best strategy is
/// using the protocols directly
pub struct TorControlStream(pub TcpStream);

/// This takes inpiration from Python's old tor stem library. Just rewritten. 

impl TorControlStream {
    // Having this function here also helps with debugging the protocols

    fn write(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        // println!("[DEBUG] TorControlStream: {:?}", String::from_utf8_lossy(buf));
        self.0.write(buf)?;
        self.check_resp()
    }

    pub fn check_resp(&mut self) -> anyhow::Result<()> {
        let mut buf: [u8; 8] = [0; 8];
        self.0.read(&mut buf)?;
        // debug!("buf {:?} starts with b\"250 OK\"", buf);
        if !buf.starts_with(b"250 OK") {
            return Err(TorControlError::ControlError {
                buf: String::from_utf8_lossy(&buf).to_string(),
            }
            .into());
        }
        Ok(())
    }

    pub fn set_authentication(&mut self, auth: Option<String>) -> anyhow::Result<()> {
        self.0.write(b"AUTHENTICATE")?;
        match auth {
            Some(pass) => {
                self.0.write(format!(" \"{}\"\r\n", &pass).as_bytes())?;
            }
            None => {
                self.0.write(b"\r\n")?;
            }
        }
        self.check_resp()
    }

    pub fn set_options(
        &mut self,
        params: Vec<(String, String)>,
        reset: bool,
    ) -> anyhow::Result<()> {
        let mut query_construct: Vec<String> = match reset {
            true => {
                vec!["RESETCONF".to_string()]
            }
            false => {
                vec!["SETCONF".to_string()]
            }
        };

        query_construct.extend(
            params
                .iter()
                .map(|(p, v)| format!("{}=\"{}\"", p, v.trim())),
        );
        
        self.0.write(query_construct.join(" ").as_bytes())?;
        self.write(b"\r\n")
    }

    pub fn add_hidden_service(
        &mut self,
        server_port: u16,
        server_host: Option<String>,
        hs_dir: &Option<std::path::PathBuf>,
    ) -> anyhow::Result<String> {
        // kind of tired of the borrow checker for rn...
        let host = Cow::from(server_host.unwrap_or("127.0.0.1".to_string()));

        let mut hs_dir = hs_dir.clone().unwrap_or(std::env::current_dir()?.join(".hidden"));
        if !hs_dir.exists(){
            std::fs::create_dir(&hs_dir)?;
        }

        // Windows Paths love to screw with the Controller's inernal the parser, (This is bad!)
        // These functions should have zero effects on Unix Operating Systems.
        // Converting windows paths to posix fixes everything...

        let hidden_service_dir = hs_dir.to_string_lossy().replace("\\", "/");

        
        self.set_options(
            vec![
                ("HiddenServiceDir".to_string(), hidden_service_dir),
                (
                    "HiddenServicePort".to_string(),
                    format!("80 {}:{}", host, server_port),
                ),
            ],
            false,
        )?;

        // Let's go read out the host's name
        hs_dir.push("hostname");
        let mut hostname = String::new();

        std::fs::File::open(hs_dir)?.read_to_string(&mut hostname)?;

        Ok(hostname)
    }
}

/// Returns A daemon and prints out the naem of the hidden service created.
pub fn setup_tor_daemon(args: &Args) -> anyhow::Result<TorProcess> {
    let tor_path = which::which(format!("tor{}", std::env::consts::EXE_SUFFIX))?;
    // TODO: Mutate and allow path names in the future?
    let data_path = TempDir::new("torrc")?;

    let default_torrc = data_path.path().join("default_torrc");
    {
        let _ = std::fs::File::create(&default_torrc)?;
    }
    let torrc = data_path.path().join("torrc");
    {
        let _ = std::fs::File::create(&torrc)?;
    }
    let tor_daemon = TorProcess(
        Command::new(tor_path)
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .arg("--defaults-torrc")
            .arg(default_torrc)
            // location of torrc
            .arg("--torrc-file")
            .arg(torrc)
            // enable networking
            .arg("DisableNetwork")
            .arg("0")
            // root data directory
            .arg("DataDirectory")
            .arg(data_path.path())
            .arg("SocksPort")
            .arg(&args.tor_socket_port.to_string())
            // control port
            .arg("ControlPort")
            .arg(&args.tor_client_port.to_string())
            .arg("__OwningControllerProcess")
            .arg(process::id().to_string())
            .spawn()?,
        data_path,
        /* Process is alive */
        false
    );

    // Will be needing this information later...
    let control_addr = format!("127.0.0.1:{}", args.tor_client_port);
    let tor_config = LegacyTorClientConfig::SystemTor {
        tor_socks_addr: std::net::SocketAddr::from_str(format!("127.0.0.1:9050").as_str())?,
        tor_control_addr: std::net::SocketAddr::from_str(&control_addr)?,
        // Leave blank if there is not password. it's not
        tor_control_passwd: args.tor_password.clone().unwrap_or("".to_string()),
    };

    let mut tor_provider = LegacyTorClient::new(tor_config)?;

    let mut bootstrap_complete = false;
    println!("DAEMON IS LAUNCHING...");

    while !bootstrap_complete {
        for event in tor_provider.update()?.iter() {
            match event {
                TorEvent::BootstrapStatus {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Server Provider BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                TorEvent::BootstrapComplete => {
                    println!("Server Provider Bootstrap Complete!");
                    bootstrap_complete = true;
                }
                TorEvent::LogReceived { line } => {
                    println!("--- {}", line);
                }
                _ => {}
            }
        }
    }

    // Instead of neeing to provide a listener it makes more sense to manipulate
    // the controller ourselves beyond this point. This way the server code is
    // not being interlaced and can theoretically be alllowed to work seperately
    // Opening and closing the control socket does the trick :)
    {
        debug!("Openting Controller");
        let mut control_sock = TorControlStream(TcpStream::connect(control_addr)?);
        debug!("Setting Auth");
        control_sock.set_authentication(args.tor_password.clone())?;
        debug!("Launching Service");
        let hostname=control_sock.add_hidden_service(
            // If your not familliar with what were doing this technqiue
            // it's called port-forwarding
            args.port,
            None,
            &args.hs_path
        )?;
        println!("Tor Hidden Service is now hosting at: \"{hostname}\"");
    }
    Ok(tor_daemon)
}
