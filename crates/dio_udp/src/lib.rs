#![forbid(unsafe_code)]

use dio_core::FrameError;

#[derive(Debug)]
pub enum UdpError {
    Io(std::io::Error),
    Frame(FrameError),
}

#[cfg(feature = "udp")]
mod udp {
    use std::net::{SocketAddr, UdpSocket};

    use dio_core::RecordFrame;

    use crate::UdpError;

    pub struct UdpOneWayWriter {
        socket: UdpSocket,
        target: SocketAddr,
    }

    impl UdpOneWayWriter {
        pub fn bind(bind_addr: SocketAddr, target: SocketAddr) -> Result<Self, UdpError> {
            let socket = UdpSocket::bind(bind_addr).map_err(UdpError::Io)?;
            Ok(Self { socket, target })
        }

        pub fn send(&self, frame: &RecordFrame) -> Result<(), UdpError> {
            let bytes = frame.encode().map_err(UdpError::Frame)?;
            self.socket
                .send_to(&bytes, self.target)
                .map(|_| ())
                .map_err(UdpError::Io)
        }
    }

    pub struct UdpOneWayReader {
        socket: UdpSocket,
        max_datagram: usize,
    }

    impl UdpOneWayReader {
        pub fn bind(bind_addr: SocketAddr) -> Result<Self, UdpError> {
            let socket = UdpSocket::bind(bind_addr).map_err(UdpError::Io)?;
            Ok(Self {
                socket,
                max_datagram: 65_535,
            })
        }

        pub fn with_max_datagram(mut self, max_datagram: usize) -> Self {
            self.max_datagram = max_datagram;
            self
        }

        pub fn recv(&self) -> Result<RecordFrame, UdpError> {
            let mut buffer = vec![0_u8; self.max_datagram];
            let (len, _) = self.socket.recv_from(&mut buffer).map_err(UdpError::Io)?;
            RecordFrame::decode(&buffer[..len]).map_err(UdpError::Frame)
        }
    }
}

#[cfg(feature = "udp")]
pub use udp::{UdpOneWayReader, UdpOneWayWriter};
