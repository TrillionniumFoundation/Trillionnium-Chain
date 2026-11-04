use std::net::{TcpStream,TcpListener,Shutdown};
use std::io::Write;
type Result<T> = std::result::Result<T,Box<dyn std::error::Error>>;
fn caller_write_half_open(socket: &TcpStream) -> Result<bool> {
    match socket.peek(&mut [0; 1]) {
        Ok(0) => Ok(false),
        Err(e)
            if !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Err(e.into())
        }
        _ => Ok(true),
    }
}
fn main() {
 let listener=TcpListener::bind("127.0.0.1:0").unwrap();
 let mut client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
 let (socket,_)=listener.accept().unwrap();
 client.write_all(b"X").unwrap();
 client.shutdown(Shutdown::Write).unwrap();
 assert!(!caller_write_half_open(&socket).unwrap(), "completed-request trailing byte must not hide closed caller write-half");
}
