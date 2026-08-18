//! A real networked complaint/disclosure round for the DKG complaint
//! protocol -- the piece the module docs (`src/lib.rs`) name as still
//! reference-implementation-only: "what it does *not* include is the
//! broadcast transport itself... reaching every honest participant with the
//! same broadcast values... is the caller's problem." This example is that
//! transport, not just an assertion that one is possible: five participants,
//! each its own OS thread with its own socket to a small broadcast relay,
//! exchange a real [`Complaint`] and the accused dealer's real
//! [`Dealer::share_for`] disclosure over actual TCP connections, and every
//! participant independently computes the same [`ComplaintVerdict`] from
//! what it received over the wire -- matching
//! `complaint_resolution_agrees_with_the_batch_identify_faulty_dealers_path`'s
//! in-process result, but with the broadcast round now real.
//!
//! The relay only ever forwards [`Complaint`]/disclosure messages -- exactly
//! the values the module docs already call "safe to broadcast" (a Feldman
//! share reveals nothing on its own). It never sees a dealer's private
//! polynomial or a participant's raw per-dealer shares from the earlier
//! reveal round, which stays local to this example's `main()` the same way
//! every other test in this crate keeps it local (module docs: "this crate
//! does not do networking" -- only the complaint round, which *is* public
//! by design, is networked here).
//!
//! Run with:
//!
//!     cargo run -p novachannel-mpc --example networked_complaint

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use novachannel_mpc::{resolve_complaint, Complaint, ComplaintVerdict, Dealer, ParticipantId};

const OP_COMPLAINT: u8 = 0;
const OP_DISCLOSURE: u8 = 1;

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

fn encode_complaint(c: &Complaint) -> Vec<u8> {
    let mut out = vec![OP_COMPLAINT];
    out.extend_from_slice(&c.accuser.to_be_bytes());
    out.extend_from_slice(&(c.dealer_index as u32).to_be_bytes());
    out.extend_from_slice(&c.received_share.to_bytes());
    out
}

fn encode_disclosure(dealer_index: u32, accuser: ParticipantId, disclosed: &Scalar) -> Vec<u8> {
    let mut out = vec![OP_DISCLOSURE];
    out.extend_from_slice(&dealer_index.to_be_bytes());
    out.extend_from_slice(&accuser.to_be_bytes());
    out.extend_from_slice(&disclosed.to_bytes());
    out
}

enum Message {
    Complaint(Complaint),
    Disclosure {
        dealer_index: u32,
        accuser: ParticipantId,
        disclosed: Scalar,
    },
}

fn decode(bytes: &[u8]) -> Message {
    match bytes[0] {
        OP_COMPLAINT => {
            let accuser = ParticipantId::from_be_bytes(bytes[1..5].try_into().unwrap());
            let dealer_index = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
            let share_bytes: [u8; 32] = bytes[9..41].try_into().unwrap();
            let received_share = Scalar::from_canonical_bytes(share_bytes)
                .into_option()
                .expect("wire scalar must be canonical");
            Message::Complaint(Complaint {
                accuser,
                dealer_index,
                received_share,
            })
        }
        OP_DISCLOSURE => {
            let dealer_index = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
            let accuser = ParticipantId::from_be_bytes(bytes[5..9].try_into().unwrap());
            let share_bytes: [u8; 32] = bytes[9..41].try_into().unwrap();
            let disclosed = Scalar::from_canonical_bytes(share_bytes)
                .into_option()
                .expect("wire scalar must be canonical");
            Message::Disclosure {
                dealer_index,
                accuser,
                disclosed,
            }
        }
        other => panic!("unknown opcode {other}"),
    }
}

/// A minimal broadcast relay: every frame any connected participant sends is
/// forwarded to every other connected participant. It routes bytes; it does
/// not participate in the protocol, and (see module doc above) everything it
/// ever forwards here is already meant to be public.
fn run_relay(listener: TcpListener, n: usize, targets: Arc<Mutex<Vec<TcpStream>>>) {
    for _ in 0..n {
        let (stream, _) = listener.accept().expect("accept a participant connection");
        let read_stream = stream.try_clone().expect("clone for reading");
        targets.lock().unwrap().push(stream);
        let handler_targets = targets.clone();
        thread::spawn(move || {
            let mut read_stream = read_stream;
            loop {
                let frame = match read_frame(&mut read_stream) {
                    Ok(f) => f,
                    Err(_) => return, // participant thread finished and closed its socket
                };
                for target in handler_targets.lock().unwrap().iter() {
                    let mut w = target.try_clone().expect("clone for writing");
                    let _ = write_frame(&mut w, &frame);
                }
            }
        });
    }
}

fn main() {
    let (threshold, n) = (3u32, 5u32);
    let accuser: ParticipantId = 4;
    let faulty_dealer_index = 2usize;

    let mut dealers: Vec<Option<Dealer>> =
        (0..n).map(|_| Some(Dealer::new(threshold, n))).collect();
    let mut dealer_commitments: Vec<Vec<RistrettoPoint>> = Vec::new();
    for d in dealers.iter().flatten() {
        dealer_commitments.push(d.reveal().0);
    }

    // Simulate the faulty dealer's share to `accuser` being corrupted in
    // transit -- same fault this crate's own in-process test
    // (`complaint_resolution_agrees_with_the_batch_identify_faulty_dealers_path`)
    // uses, so the expected verdict below is directly comparable.
    let honest_share = dealers[faulty_dealer_index]
        .as_ref()
        .unwrap()
        .share_for(accuser);
    let corrupted_share = honest_share + Scalar::ONE;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the relay's local port");
    let addr = listener.local_addr().unwrap();
    let relay_targets: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
    let relay_targets_for_relay = relay_targets.clone();
    let relay_thread = thread::spawn(move || {
        run_relay(listener, n as usize, relay_targets_for_relay);
    });

    // Connect every participant's socket from the main thread first, so the
    // relay has all `n` connections established before any protocol traffic
    // starts -- avoids a race between "relay accepted everyone" and "the
    // accuser already broadcast its complaint."
    let participant_streams: Vec<TcpStream> = (0..n)
        .map(|_| TcpStream::connect(addr).expect("connect to the relay"))
        .collect();

    let faulty_dealer_commitments = dealer_commitments[faulty_dealer_index].clone();

    let handles: Vec<_> = (0..n)
        .map(|pid| {
            let mut stream = participant_streams[pid as usize]
                .try_clone()
                .expect("clone this participant's socket");
            let commitments = faulty_dealer_commitments.clone();
            let own_dealer = if pid as usize == faulty_dealer_index {
                dealers[faulty_dealer_index].take()
            } else {
                None
            };
            let is_accuser = pid == accuser;

            thread::spawn(move || -> ComplaintVerdict {
                if is_accuser {
                    let complaint = Complaint {
                        accuser,
                        dealer_index: faulty_dealer_index,
                        received_share: corrupted_share,
                    };
                    write_frame(&mut stream, &encode_complaint(&complaint))
                        .expect("broadcast the complaint");
                }

                let mut seen_complaint: Option<Complaint> = None;
                loop {
                    let frame = read_frame(&mut stream).expect("read the next broadcast frame");
                    match decode(&frame) {
                        Message::Complaint(c) => {
                            seen_complaint = Some(c);
                            // Only the accused dealer's own thread holds
                            // `own_dealer` -- everyone else's is `None`.
                            if let Some(dealer) = &own_dealer {
                                let disclosed = dealer.share_for(c.accuser);
                                write_frame(
                                    &mut stream,
                                    &encode_disclosure(faulty_dealer_index as u32, c.accuser, &disclosed),
                                )
                                .expect("broadcast the dealer's disclosure");
                            }
                        }
                        Message::Disclosure {
                            dealer_index,
                            accuser: disclosed_for,
                            disclosed,
                        } => {
                            let complaint = seen_complaint
                                .expect("a disclosure implies its complaint was seen first over this broadcast order");
                            assert_eq!(dealer_index as usize, faulty_dealer_index);
                            assert_eq!(disclosed_for, complaint.accuser);
                            return resolve_complaint(&commitments, &complaint, &disclosed);
                        }
                    }
                }
            })
        })
        .collect();

    let verdicts: Vec<ComplaintVerdict> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    relay_thread.join().unwrap();

    assert!(verdicts.iter().all(|v| *v == verdicts[0]));
    assert!(verdicts[0].is_faulty());
    println!(
        "networked DKG complaint round: all {} participants independently reached the same \
         verdict over real TCP broadcasts: {:?}",
        n, verdicts[0]
    );
}
