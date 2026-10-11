//! Two peers perform a mutually authenticated hybrid handshake over TCP,
//! then exchange a few AEAD-protected records. Run with:
//!
//!     cargo run --example echo

use novachannel::{handshake, identity::Identity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(bytes).await
}

async fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_identity = Identity::generate();
    let server_public = server_identity.public();
    let client_identity = Identity::generate();
    let client_public = client_identity.public();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let msg1 = read_frame(&mut stream).await.unwrap();
        // Pin the expected client identity, learned out-of-band.
        let (resp_state, msg2) =
            handshake::responder_respond(&server_identity, Some(client_public), &msg1).unwrap();
        write_frame(&mut stream, &msg2).await.unwrap();

        let msg3 = read_frame(&mut stream).await.unwrap();
        let mut session = resp_state.complete(&msg3).unwrap();
        println!("server: handshake complete with authenticated peer");

        let record = read_frame(&mut stream).await.unwrap();
        let plaintext = session.receiver.open(&record).unwrap();
        println!("server received: {}", String::from_utf8_lossy(&plaintext));

        let reply = session.sender.seal(b"hello from the server").unwrap();
        write_frame(&mut stream, &reply).await.unwrap();
    });

    let mut stream = TcpStream::connect(addr).await?;
    // Pin the expected server identity, learned out-of-band.
    let (init_state, msg1) = handshake::initiator_start(Some(server_public));
    write_frame(&mut stream, &msg1).await?;

    let msg2 = read_frame(&mut stream).await?;
    let (msg3, mut session) = init_state.complete(&client_identity, &msg2)?;
    write_frame(&mut stream, &msg3).await?;
    println!("client: handshake complete with authenticated peer");

    let record = session.sender.seal(b"hello from the client")?;
    write_frame(&mut stream, &record).await?;

    let reply = read_frame(&mut stream).await?;
    let plaintext = session.receiver.open(&reply)?;
    println!("client received: {}", String::from_utf8_lossy(&plaintext));

    server_task.await?;
    Ok(())
}
