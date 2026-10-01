use std::collections::VecDeque;

use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};

pub struct QueueDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    capabilities: DeviceCapabilities,
}

impl QueueDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            capabilities: device_capabilities(mtu),
        }
    }

    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }
}

fn device_capabilities(mtu: usize) -> DeviceCapabilities {
    let mut capabilities = DeviceCapabilities::default();

    capabilities.max_transmission_unit = mtu;
    capabilities.medium = Medium::Ip;

    capabilities
}

pub struct QueueRxToken {
    packet: Vec<u8>,
}

impl RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct QueueTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for QueueTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];

        let result = f(&mut packet);

        self.queue.push_back(packet);

        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = QueueRxToken
    where
        Self: 'a;

    type TxToken<'a>
        = QueueTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;

        Some((
            QueueRxToken { packet },
            QueueTxToken {
                queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}
