// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on https://github.com/minato128/rust-dogstatsd
// forked from https://github.com/markstory/rust-statsd
//
extern crate rand;

use std::{
    error, fmt,
    io::Error,
    mem,
    net::{AddrParseError, SocketAddr, ToSocketAddrs, UdpSocket},
};

use log::*;

pub type Tags<'a> = Option<&'a Vec<&'a str>>;

#[derive(Debug)]
pub enum StatsdError {
    IoError(Error),
    AddrParseError(String),
}

pub trait EventSink {
    fn send(&mut self, data: String);
    fn flush(&mut self);
}

impl From<AddrParseError> for StatsdError {
    fn from(_: AddrParseError) -> StatsdError {
        StatsdError::AddrParseError("Address parsing error".to_string())
    }
}

impl From<Error> for StatsdError {
    fn from(err: Error) -> StatsdError {
        StatsdError::IoError(err)
    }
}

impl fmt::Display for StatsdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StatsdError::IoError(ref e) => write!(f, "{}", e),
            StatsdError::AddrParseError(ref e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for StatsdError {}

/// Client socket for statsd servers.
///
/// After creating a metric you can use `Client`
/// to send metrics to the configured statsd server
pub struct Client<T: EventSink> {
    sink: T,
    prefix: String,
    constant_tags: Vec<String>,
}

pub struct UdpEventSink {
    socket: UdpSocket,
    server_address: SocketAddr,
}

impl UdpEventSink {
    pub fn new<T: ToSocketAddrs>(host: T) -> Result<UdpEventSink, StatsdError> {
        let server_address = host
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| StatsdError::AddrParseError("Address parsing error".to_string()))?;

        // Bind to a generic port as we'll only be writing on this
        // socket.
        let socket = if server_address.is_ipv4() {
            UdpSocket::bind("0.0.0.0:0")?
        } else {
            UdpSocket::bind("[::]:0")?
        };
        Ok(UdpEventSink {
            socket,
            server_address,
        })
    }
}

impl EventSink for UdpEventSink {
    fn send(&mut self, data: String) {
        let _ = self.socket.send_to(data.as_bytes(), self.server_address);
    }

    fn flush(&mut self) {
        // nothing to flush, everything was sent immediately
    }
}

pub struct PipelineSink<'a, T: EventSink> {
    sink: &'a mut T,
    max_udp_size: usize,
    buffer: String,
}

impl<'a, T: EventSink> PipelineSink<'a, T> {
    fn new(sink: &'a mut T) -> PipelineSink<'a, T> {
        const COMMODITY_INTERNET_PACKET_SIZE: usize = 512;

        Self::new_with_size(sink, COMMODITY_INTERNET_PACKET_SIZE)
    }

    /// See https://github.com/statsd/statsd/blob/master/docs/metric_types.md#multi-metric-packets
    /// for guidance. 512 is a safe minimum.
    fn new_with_size(sink: &'a mut T, max_udp_size: usize) -> PipelineSink<'a, T> {
        Self {
            sink,
            max_udp_size,
            buffer: Default::default(),
        }
    }
}

impl<T: EventSink> Drop for PipelineSink<'_, T> {
    fn drop(&mut self) {
        self.flush();
    }
}

impl<T: EventSink> EventSink for PipelineSink<'_, T> {
    fn send(&mut self, data: String) {
        if data.len() > self.max_udp_size {
            warn!(
                "Not able to send metric packet of length {}, as was over udp size {}",
                data.len(),
                self.max_udp_size
            );
            return;
        }

        if self.buffer.len() + data.len() >= self.max_udp_size {
            // cannot buffer, must send this
            let buffer_contents = mem::replace(&mut self.buffer, data);
            self.sink.send(buffer_contents);
        } else {
            // queue for later
            if self.buffer.is_empty() {
                self.buffer = data;
            } else {
                self.buffer += "\n";
                self.buffer += data.as_str();
            }
        }
    }

    fn flush(&mut self) {
        if !self.buffer.is_empty() {
            let buffer_contents = mem::take(&mut self.buffer);
            self.sink.send(buffer_contents);
        }
    }
}

impl<E: EventSink> Client<E> {
    /// Construct a new statsd client given a sink
    pub fn new(sink: E, prefix: &str, constant_tags: Option<Vec<&str>>) -> Client<E> {
        Client {
            sink,
            prefix: prefix.to_string(),
            constant_tags: constant_tags
                .unwrap_or_default()
                .iter()
                .map(|x| x.to_string())
                .collect(),
        }
    }

    /// Increment a metric by 1
    ///
    /// This modifies a counter with an effective sampling rate of 1.0.
    pub fn incr(&mut self, metric: &str, tags: &Option<Vec<&str>>) {
        self.count(metric, 1.0, tags);
    }

    /// Decrement a metric by 1
    ///
    /// This modifies a counter with an effective sampling rate of 1.0.
    pub fn decr(&mut self, metric: &str, tags: &Option<Vec<&str>>) {
        self.count(metric, -1.0, tags);
    }

    /// Modify a counter by `value`.
    ///
    /// Will increment or decrement a counter by `value` with a sampling rate of 1.0.
    pub fn count(&mut self, metric: &str, value: f64, tags: &Option<Vec<&str>>) {
        let data = self.prepare_with_tags(format!("{}:{}|c", metric, value), tags);
        self.send(data);
    }

    /// Set a gauge value.
    pub fn gauge(&mut self, metric: &str, value: f64, tags: &Option<Vec<&str>>) {
        let data = self.prepare_with_tags(format!("{}:{}|g", metric, value), tags);
        self.send(data);
    }

    /// Send a timer value.
    pub fn timer(&mut self, metric: &str, milliseconds: f64, tags: &Option<Vec<&str>>) {
        let data = self.prepare_with_tags(format!("{}:{}|ms", metric, milliseconds), tags);
        self.send(data);
    }

    /// Send a timer value at a specified sample rate in 0..1 range.
    pub fn timer_at_rate(&mut self, metric: &str, milliseconds: f64, rate: f64, tags: Tags) {
        let data =
            self.prepare_with_tags_ref(format!("{}:{}|ms|@{}", metric, milliseconds, rate), tags);
        self.send(data);
    }

    fn prepare<T: AsRef<str>>(&self, data: T) -> String {
        if self.prefix.is_empty() {
            data.as_ref().to_string()
        } else {
            format!("{}.{}", self.prefix, data.as_ref())
        }
    }

    fn prepare_with_tags<T: AsRef<str>>(&self, data: T, tags: &Option<Vec<&str>>) -> String {
        self.append_tags(self.prepare(data), tags)
    }

    fn prepare_with_tags_ref<T: AsRef<str>>(&self, data: T, tags: Tags) -> String {
        self.append_tags_ref(self.prepare(data), tags)
    }

    fn append_tags_ref<T: AsRef<str>>(&self, data: T, tags: Tags) -> String {
        if self.constant_tags.is_empty() && tags.is_none() {
            data.as_ref().to_string()
        } else {
            let mut all_tags = self.constant_tags.clone();
            if let Some(v) = tags {
                for tag in v {
                    all_tags.push(tag.to_string());
                }
            };

            format!("{}|#{}", data.as_ref(), all_tags.join(","))
        }
    }

    fn append_tags<T: AsRef<str>>(&self, data: T, tags: &Option<Vec<&str>>) -> String {
        if self.constant_tags.is_empty() && tags.is_none() {
            data.as_ref().to_string()
        } else {
            let mut all_tags = self.constant_tags.clone();
            match tags {
                Some(v) => {
                    for tag in v {
                        all_tags.push(tag.to_string());
                    }
                }
                None => {
                    // nothing to do
                }
            }
            format!("{}|#{}", data.as_ref(), all_tags.join(","))
        }
    }

    /// Send data along to the sink.
    fn send(&mut self, data: String) {
        self.sink.send(data);
    }

    /// Get a pipeline struct that allows optimizes the number of UDP
    /// packets used to send multiple metrics.
    pub fn pipeline(&mut self) -> Client<PipelineSink<E>> {
        Client {
            sink: PipelineSink::new(&mut self.sink),
            prefix: self.prefix.clone(),
            constant_tags: self.constant_tags.clone(),
        }
    }

    pub fn pipeline_client_of_size(&mut self, max_udp_size: usize) -> Client<PipelineSink<E>> {
        Client {
            sink: PipelineSink::new_with_size(&mut self.sink, max_udp_size),
            prefix: self.prefix.clone(),
            constant_tags: self.constant_tags.clone(),
        }
    }

    /// Send a histogram value.
    pub fn histogram(&mut self, metric: &str, value: f64, tags: &Option<Vec<&str>>) {
        let data = self.prepare_with_tags(format!("{}:{}|h", metric, value), tags);
        self.send(data);
    }

    /// Send a histogram value at a specified sample rate in 0..1 range.
    pub fn histogram_at_rate(&mut self, metric: &str, value: f64, rate: f64, tags: Tags) {
        let data = self.prepare_with_tags_ref(format!("{}:{}|h|@{}", metric, value, rate), tags);
        self.send(data);
    }

    /// Send a distribution value.
    pub fn distribution(&mut self, metric: &str, value: f64, tags: &Option<Vec<&str>>) {
        let data = self.prepare_with_tags(format!("{}.d:{}|d", metric, value), tags);
        self.send(data);
    }

    /// Send a distribution value at a specified sample rate in 0..1 range.
    pub fn distribution_at_rate(&mut self, metric: &str, value: f64, rate: f64, tags: Tags) {
        let data = self.prepare_with_tags_ref(format!("{}.d:{}|d|@{}", metric, value, rate), tags);
        self.send(data);
    }

    /// Send a event.
    pub fn event(
        &mut self,
        title: &str,
        text: &str,
        alert_type: AlertType,
        tags: &Option<Vec<&str>>,
    ) {
        let mut d = vec![];
        d.push(format!("_e{{{},{}}}:{}", title.len(), text.len(), title));
        d.push(text.to_string());
        if alert_type != AlertType::Info {
            d.push(format!("t:{}", alert_type.to_string().to_lowercase()))
        }
        let event_with_tags = self.append_tags(d.join("|"), tags);
        self.send(event_with_tags)
    }

    /// Send a service check.
    pub fn service_check(
        &mut self,
        service_check_name: &str,
        status: ServiceCheckStatus,
        tags: &Option<Vec<&str>>,
    ) {
        let mut d = vec![];
        let status_code = (status as u32).to_string();
        d.push("_sc");
        d.push(service_check_name);
        d.push(&status_code);
        let sc_with_tags = self.append_tags(d.join("|"), tags);
        self.send(sc_with_tags)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlertType {
    Info,
    Error,
    Warning,
    Success,
}

impl fmt::Display for AlertType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceCheckStatus {
    Ok = 0,
    Warning = 1,
    Critical = 2,
    Unknown = 3,
}

#[cfg(test)]
mod test {
    extern crate rand;

    use std::{cell::RefCell, rc::Rc};

    use super::*;

    struct MockServer {
        packets: Rc<RefCell<Vec<String>>>,
    }

    struct MockUdpPort {
        packets: Rc<RefCell<Vec<String>>>,
    }

    impl MockServer {
        fn new() -> MockServer {
            Self {
                packets: Default::default(),
            }
        }

        fn new_port(&self) -> MockUdpPort {
            MockUdpPort {
                packets: Rc::clone(&self.packets),
            }
        }

        fn read_packet(&mut self) -> String {
            let mut cell = self.packets.borrow_mut();
            cell.remove(0)
        }

        fn expect_no_more_packets(&self) {
            assert_eq!(0, self.packets.borrow().len());
        }
    }

    impl EventSink for MockUdpPort {
        fn send(&mut self, data: String) {
            self.packets.borrow_mut().push(data);
        }

        fn flush(&mut self) {}
    }

    #[test]
    fn sending_gauge() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        client.gauge("metric", 9.1, &None);

        assert_eq!("myapp.metric:9.1|g", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_gauge_with_tags() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", Some(vec!["tag1", "tag2:value"]));

        client.gauge("metric", 9.1, &Some(vec!["tag3", "tag4:value"]));

        assert_eq!(
            "myapp.metric:9.1|g|#tag1,tag2:value,tag3,tag4:value",
            server.read_packet()
        );
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_gauge_without_prefix() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "", None);

        client.gauge("metric", 9.1, &None);

        assert_eq!("metric:9.1|g", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_incr() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        client.incr("metric", &None);

        assert_eq!("myapp.metric:1|c", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_decr() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        client.decr("metric", &None);

        assert_eq!("myapp.metric:-1|c", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_count() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        client.count("metric", 12.2, &None);

        assert_eq!("myapp.metric:12.2|c", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_count_with_tags() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", Some(vec!["tag1", "tag2:value"]));

        client.count("metric", 12.2, &Some(vec!["tag3", "tag4:value"]));

        assert_eq!(
            "myapp.metric:12.2|c|#tag1,tag2:value,tag3,tag4:value",
            server.read_packet()
        );
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_timer() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        client.timer("metric", 21.39, &None);

        assert_eq!("myapp.metric:21.39|ms", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_timer_at_rate() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        client.timer_at_rate("metric", 21.39, 0.123, None);

        assert_eq!("myapp.metric:21.39|ms|@0.123", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_histogram() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        // without tags
        client.histogram("metric", 9.1, &None);
        assert_eq!("myapp.metric:9.1|h", server.read_packet());
        server.expect_no_more_packets();

        // with tags
        client.histogram_at_rate("metric", 9.1, 0.2, Some(&vec!["tag1", "tag2:test"]));
        assert_eq!(
            "myapp.metric:9.1|h|@0.2|#tag1,tag2:test",
            server.read_packet()
        );
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_histogram_with_constant_tags() {
        let mut server = MockServer::new();
        let mut client = Client::new(
            server.new_port(),
            "myapp",
            Some(vec!["tag1common", "tag2common:test"]),
        );

        // without tags
        client.histogram("metric", 9.1, &None);
        assert_eq!(
            "myapp.metric:9.1|h|#tag1common,tag2common:test",
            server.read_packet()
        );
        server.expect_no_more_packets();

        // with tags
        let tags = &Some(vec!["tag1", "tag2:test"]);
        client.histogram("metric", 9.1, tags);
        assert_eq!(
            "myapp.metric:9.1|h|#tag1common,tag2common:test,tag1,tag2:test",
            server.read_packet()
        );
        server.expect_no_more_packets();

        // repeat
        client.histogram_at_rate("metric", 19.12, 0.2, tags.as_ref());
        assert_eq!(
            "myapp.metric:19.12|h|@0.2|#tag1common,tag2common:test,tag1,tag2:test",
            server.read_packet()
        );
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_distribution() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        // without tags
        client.distribution("metric", 9.1, &None);
        assert_eq!("myapp.metric.d:9.1|d", server.read_packet());
        server.expect_no_more_packets();

        // with tags
        client.distribution_at_rate("metric", 9.1, 0.1, Some(&vec!["tag1", "tag2:test"]));
        assert_eq!(
            "myapp.metric.d:9.1|d|@0.1|#tag1,tag2:test",
            server.read_packet()
        );
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_event_with_tags() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        client.event(
            "Title Test",
            "Text ABC",
            AlertType::Error,
            &Some(vec!["tag1", "tag2:test"]),
        );

        assert_eq!(
            "_e{10,8}:Title Test|Text ABC|t:error|#tag1,tag2:test",
            server.read_packet()
        );
        server.expect_no_more_packets();
    }

    #[test]
    fn sending_service_check_with_tags() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);

        client.service_check(
            "Service.check.name",
            ServiceCheckStatus::Critical,
            &Some(vec!["tag1", "tag2:test"]),
        );

        assert_eq!(
            "_sc|Service.check.name|2|#tag1,tag2:test",
            server.read_packet()
        );
        server.expect_no_more_packets();
    }

    #[test]
    fn pipeline_sending_gauge() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);
        let mut pipeline = client.pipeline();
        pipeline.gauge("metric", 9.1, &None);
        drop(pipeline);

        assert_eq!("myapp.metric:9.1|g", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn pipeline_sending_histogram() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);
        let mut pipeline = client.pipeline();
        pipeline.histogram("metric", 9.1, &None);
        drop(pipeline);

        assert_eq!("myapp.metric:9.1|h", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn pipeline_sending_multiple_data() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);
        let mut pipeline = client.pipeline();
        pipeline.gauge("metric", 9.1, &None);
        pipeline.count("metric", 12.2, &None);
        drop(pipeline);

        assert_eq!(
            "myapp.metric:9.1|g\nmyapp.metric:12.2|c",
            server.read_packet()
        );
        server.expect_no_more_packets();
    }

    #[test]
    fn pipeline_set_max_udp_size() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);
        let mut pipeline = client.pipeline_client_of_size(20);
        pipeline.gauge("metric", 9.1, &None);
        pipeline.count("metric", 12.2, &None);
        drop(pipeline);

        assert_eq!("myapp.metric:9.1|g", server.read_packet());
        assert_eq!("myapp.metric:12.2|c", server.read_packet());
        server.expect_no_more_packets();
    }

    #[test]
    fn pipeline_send_metric_after_pipeline() {
        let mut server = MockServer::new();
        let mut client = Client::new(server.new_port(), "myapp", None);
        let mut pipeline = client.pipeline();

        pipeline.gauge("load", 9.0, &None);
        pipeline.count("customers", 7.0, &None);
        drop(pipeline);

        // Should still be able to send metrics
        // with the client.
        client.count("customers", 6.0, &None);

        assert_eq!("myapp.load:9|g\nmyapp.customers:7|c", server.read_packet());
        assert_eq!("myapp.customers:6|c", server.read_packet());
        server.expect_no_more_packets();
    }
}
