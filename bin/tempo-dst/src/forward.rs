// SPDX-License-Identifier: GPL-2.0

//! `tempo-dst tcp-forward LISTEN=UPSTREAM...`: a plain TCP forwarder (a
//! compose service), so containers in their own network namespaces reach a
//! service of the guest host network. The multi-sequencer zone's
//! sequencers reach the L1 WebSocket (`127.0.0.1:8546`) through it on the
//! cluster network's gateway, one port per sequencer, so the network
//! nemesis can fault each sequencer's L1 link in its own namespace.
//!
//! It adds no behavior of its own: bytes are copied as they come, each
//! connection closes when either side does. Deterministic like every guest
//! process (no clocks, no randomness).

use std::{
    io,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
};

/// Parses `LISTEN=UPSTREAM` pairs.
pub fn parse(args: &[String]) -> Result<Vec<(SocketAddr, SocketAddr)>, String> {
    if args.is_empty() {
        return Err("want LISTEN=UPSTREAM pairs".into());
    }
    args.iter()
        .map(|a| {
            let (l, u) = a
                .split_once('=')
                .ok_or_else(|| format!("{a:?}: want LISTEN=UPSTREAM"))?;
            Ok((
                l.parse().map_err(|e| format!("{l}: {e}"))?,
                u.parse().map_err(|e| format!("{u}: {e}"))?,
            ))
        })
        .collect()
}

fn pipe(mut from: TcpStream, mut to: TcpStream) {
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
    let _ = from.shutdown(Shutdown::Read);
}

fn serve(listener: TcpListener, upstream: SocketAddr) {
    for client in listener.incoming() {
        let Ok(client) = client else { continue };
        std::thread::spawn(move || {
            let Ok(up) = TcpStream::connect(upstream) else {
                let _ = client.shutdown(Shutdown::Both);
                return;
            };
            let _ = client.set_nodelay(true);
            let _ = up.set_nodelay(true);
            let (Ok(c2), Ok(u2)) = (client.try_clone(), up.try_clone()) else {
                return;
            };
            let t = std::thread::spawn(move || pipe(c2, up));
            pipe(u2, client);
            let _ = t.join();
        });
    }
}

/// Binds every pair, then forwards forever.
pub fn run(args: &[String]) -> Result<(), String> {
    let pairs = parse(args)?;
    let mut handles = Vec::new();
    for (listen, upstream) in pairs {
        let l = TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
        println!("tcp-forward: {listen} -> {upstream}");
        handles.push(std::thread::spawn(move || serve(l, upstream)));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn forwards_both_directions() {
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let up = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in echo.incoming().map_while(Result::ok) {
                let mut w = s.try_clone().unwrap();
                let mut r = s;
                std::thread::spawn(move || {
                    let _ = io::copy(&mut r, &mut w);
                });
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || serve(l, up));
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"hello").unwrap();
        let mut got = [0u8; 5];
        c.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello");
    }

    #[test]
    fn parses_pairs() {
        let p = parse(&["0.0.0.0:18600=127.0.0.1:8546".into()]).unwrap();
        assert_eq!(p[0].0.port(), 18600);
        assert!(parse(&[]).is_err());
        assert!(parse(&["x".into()])
            .unwrap_err()
            .contains("LISTEN=UPSTREAM"));
    }
}
