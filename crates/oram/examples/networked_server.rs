//! A real networked `ServerStorage` implementation, run against `Client`
//! over an actual TCP socket instead of the in-process `InMemoryServer` the
//! rest of this crate's tests use.
//!
//! The module docs (`src/lib.rs`) claim "a networked deployment implements
//! the same trait over RPCs instead, and `Client`'s logic doesn't change at
//! all" — this example is that claim, not just an assertion of it:
//! `TcpServerStorage` implements `ServerStorage<Vec<u8>>` by sending
//! length-prefixed requests to a real server thread listening on a real
//! socket, and `Client<Vec<u8>, TcpServerStorage>` runs the identical
//! `read`/`write` protocol as `PathOram` does against `InMemoryServer` — no
//! new dependency, no async runtime, just `std::net`, matching the "this
//! crate does not do networking, but the split is real" boundary the module
//! docs draw.
//!
//! Run with:
//!
//!     cargo run -p novachannel-oram --example networked_server

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use novachannel_oram::{depth_for_capacity, Block, BlockId, Client, InMemoryServer, ServerStorage};

const OP_READ_AND_CLEAR: u8 = 0;
const OP_WRITE: u8 = 1;

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn encode_blocks(blocks: &[Block<Vec<u8>>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(blocks.len() as u32).to_be_bytes());
    for block in blocks {
        out.extend_from_slice(&block.id.to_be_bytes());
        out.extend_from_slice(&(block.value.len() as u32).to_be_bytes());
        out.extend_from_slice(&block.value);
    }
    out
}

fn decode_blocks(bytes: &[u8]) -> Vec<Block<Vec<u8>>> {
    let mut pos = 0;
    let count = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let id = BlockId::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let value = bytes[pos..pos + len].to_vec();
        pos += len;
        blocks.push(Block { id, value });
    }
    blocks
}

/// Runs the server side of the protocol against one connection, backed by a
/// real `InMemoryServer` the client on the other end of the socket never
/// touches directly.
fn serve(mut stream: TcpStream, mut server: InMemoryServer<Vec<u8>>) {
    loop {
        let request = match read_frame(&mut stream) {
            Ok(bytes) => bytes,
            Err(_) => return, // client closed the connection -- expected at shutdown
        };
        match request[0] {
            OP_READ_AND_CLEAR => {
                let node = u32::from_be_bytes(request[1..5].try_into().unwrap()) as usize;
                let blocks = server.read_and_clear(node);
                write_frame(&mut stream, &encode_blocks(&blocks)).unwrap();
            }
            OP_WRITE => {
                let node = u32::from_be_bytes(request[1..5].try_into().unwrap()) as usize;
                let blocks = decode_blocks(&request[5..]);
                server.write(node, blocks);
                write_frame(&mut stream, &[]).unwrap();
            }
            other => panic!("unknown opcode {other}"),
        }
    }
}

/// Client-side `ServerStorage`: every bucket read/write this drives crosses
/// a real socket to the thread running [`serve`] above.
struct TcpServerStorage {
    stream: TcpStream,
    bucket_capacity: usize,
}

impl ServerStorage<Vec<u8>> for TcpServerStorage {
    fn read_and_clear(&mut self, node: usize) -> Vec<Block<Vec<u8>>> {
        let mut request = vec![OP_READ_AND_CLEAR];
        request.extend_from_slice(&(node as u32).to_be_bytes());
        write_frame(&mut self.stream, &request).unwrap();
        let response = read_frame(&mut self.stream).unwrap();
        decode_blocks(&response)
    }

    fn write(&mut self, node: usize, blocks: Vec<Block<Vec<u8>>>) {
        let mut request = vec![OP_WRITE];
        request.extend_from_slice(&(node as u32).to_be_bytes());
        request.extend_from_slice(&encode_blocks(&blocks));
        write_frame(&mut self.stream, &request).unwrap();
        read_frame(&mut self.stream).unwrap(); // ack
    }

    fn bucket_capacity(&self) -> usize {
        self.bucket_capacity
    }
}

fn main() {
    let capacity_leaves = 8u64;
    let bucket_capacity = 4usize;
    let depth = depth_for_capacity(capacity_leaves);
    let num_leaves = 1u64 << depth;
    let num_nodes = (2 * num_leaves) as usize;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local port");
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept the client connection");
        let server = InMemoryServer::new(num_nodes, bucket_capacity);
        serve(stream, server);
    });

    let stream = TcpStream::connect(addr).expect("connect to the server thread");
    let storage = TcpServerStorage {
        stream,
        bucket_capacity,
    };
    let mut client: Client<Vec<u8>, TcpServerStorage> = Client::with_server(depth, storage);

    let mut rng = rand::rng();
    let writes: &[(BlockId, &[u8])] = &[
        (0, b"first record, over the wire"),
        (1, b"second record, over the wire"),
        (2, b"third record, over the wire"),
    ];

    for (id, value) in writes {
        client.write(*id, value.to_vec(), &mut rng);
    }
    // Re-read every record after every write has re-randomized its leaf and
    // touched a fresh path -- the values still round-trip correctly through
    // the real socket, exactly as `PathOram`'s in-process tests already
    // establish against `InMemoryServer`.
    for (id, value) in writes {
        let read_back = client.read(*id, &mut rng).expect("value was just written");
        assert_eq!(read_back, value.to_vec());
    }

    println!(
        "networked ServerStorage: {} records round-tripped correctly over a real TCP socket \
         (stash size {})",
        writes.len(),
        client.stash_len()
    );

    drop(client); // closes the socket, unblocking the server thread's next read_frame
    server_thread.join().unwrap();
}
